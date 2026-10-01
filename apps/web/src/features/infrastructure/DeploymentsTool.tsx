/**
 * DeploymentsTool — the Deployments / Infrastructure workbench surface
 * (#/app/:id/workbench/deployments; design/infrastructure.md — binding).
 *
 * Distinct truths side by side — repository identity + cleanliness, target
 * identity, VM power, SSH readiness, health, authorization, plan, approval,
 * run progress, outcome, receipt — each with its own honest semantic label,
 * never compressed into one green/red verdict.
 *
 * Every operation routes through the plan workflow (select → prepare →
 * identity → steps → risk → effects → rollback → approval when required →
 * run → progress → final state → receipt). Read-only inspections need no
 * approval; routine operations may be covered by the daily-driver
 * authorization; destruction always needs typed confirmation + its own
 * approval. No palette command or button runs anything directly.
 */
import {
  Info,
  FolderGit2,
  GitBranch,
  HeartPulse,
  MonitorCog,
  MoreHorizontal,
  Play,
  RefreshCw,
  Server,
  ShieldCheck,
  Square,
  Unplug,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

import type { InfrastructureOperation } from '@/client'
import { getClient } from '@/client'
import {
  ConfirmDialog,
  CopyButton,
  ErrorState,
  InlineNotice,
  SkeletonRows,
  StatusBadgeFrom,
  StatusDotFrom,
  TimeAgo,
  Tooltip,
} from '@/components'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useCurrentInstance } from '@/shell/currentInstance'
import type { ShellCommand } from '@/shell/commands'
import { useRegisterCommands } from '@/shell/commands'
import { isEditableTarget, useIsMobile } from '@/shell/platform'
import { WorkbenchToolHeader } from '@/shell/workbench/ToolHeader'
import { useRegisterToolPanel } from '@/shell/workbench/WorkbenchSlots'
import type { SemanticPresentation } from '@/semantic'
import { receiptResultPresentation, repositoryCleanPresentation } from '@/semantic'

import { AuthorizationCard } from './AuthorizationCard'
import { PlanCard } from './PlanCard'
import { DeploymentsNavPanel } from './DeploymentsNavPanel'
import { useDeploymentsSelection } from './deploymentsSelection'
import type { OperationMeta } from './infrastructureModel'
import {
  OPERATION_META,
  dominantTargetPresentation,
  healthPresentation,
  repositoryPresentation,
  sshPresentation,
  vmPowerPresentation,
} from './infrastructureModel'
import { useInfrastructure } from './useInfrastructure'

export default function DeploymentsTool() {
  const params = useParams<{ instanceId: string }>()
  const { instance } = useCurrentInstance()
  const instanceId = instance?.id ?? params.instanceId ?? ''
  const navigate = useNavigate()
  const isMobile = useIsMobile()

  const infra = useInfrastructure(instanceId)
  const { target, targetUnavailable, loading, loadError, refresh } = infra

  // ── Nav panel + nav-panel → canvas plan selection ──────────────────────────
  useRegisterToolPanel('deployments', DeploymentsNavPanel)
  const requestedPlanId = useDeploymentsSelection((s) => s.requestedPlanId)
  const clearRequest = useDeploymentsSelection((s) => s.clearRequest)
  useEffect(() => {
    if (!requestedPlanId) return
    infra.selectPlan(requestedPlanId)
    clearRequest()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestedPlanId, clearRequest])

  // ── Local UI state ─────────────────────────────────────────────────────────
  const [busy, setBusy] = useState(false)
  const [opError, setOpError] = useState<string | null>(null)
  const [destroyConfirm, setDestroyConfirm] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [infoFact, setInfoFact] = useState<string | null>(null)
  const [announcement, setAnnouncement] = useState('')
  const authorizationRef = useRef<HTMLDivElement | null>(null)

  const running = infra.run?.phase === 'running' || infra.run?.phase === 'validating'
  const activePlan = useMemo(
    () => infra.plans.find((p) => p.id === infra.activePlanId) ?? null,
    [infra.plans, infra.activePlanId],
  )

  const prepare = useCallback(
    async (operation: InfrastructureOperation) => {
      setBusy(true)
      setOpError(null)
      try {
        const plan = await infra.preparePlan(operation)
        setAnnouncement(`Plan prepared: ${plan.title}. Review it below — nothing has run yet.`)
      } catch (err) {
        setOpError(err instanceof Error ? err.message : String(err))
      } finally {
        setBusy(false)
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [infra.preparePlan],
  )

  const startOperation = useCallback(
    (meta: OperationMeta) => {
      setMenuOpen(false)
      if (meta.operation === 'destroy') setDestroyConfirm(true)
      else void prepare(meta.operation)
    },
    [prepare],
  )

  // ── Palette commands (route through prepare → review; nothing runs) ────────
  const commands = useMemo<ShellCommand[]>(
    () => [
      {
        id: 'deployments.prepare_plan',
        title: 'Deployments: Prepare a plan…',
        group: 'Actions',
        icon: Server,
        keywords: ['infrastructure', 'plan', 'deploy'],
        when: () => Boolean(instanceId) && !targetUnavailable,
        run: () => setMenuOpen(true),
      },
      {
        id: 'deployments.health_check',
        title: 'Deployments: Run health check',
        group: 'Actions',
        icon: HeartPulse,
        keywords: ['infrastructure', 'health'],
        when: () => Boolean(instanceId) && !targetUnavailable && target?.vm.state === 'running',
        // Prepares the read-only plan and opens review — the Run stays explicit.
        run: () => void prepare('health_check'),
      },
      {
        id: 'deployments.open_authorization',
        title: 'Deployments: Open daily-driver authorization',
        group: 'Actions',
        icon: ShieldCheck,
        keywords: ['infrastructure', 'authorization', 'grant'],
        when: () => Boolean(instanceId) && !targetUnavailable,
        run: () => {
          authorizationRef.current?.scrollIntoView({ block: 'start' })
          authorizationRef.current?.focus({ preventScroll: true })
        },
      },
      {
        id: 'deployments.refresh',
        title: 'Deployments: Refresh state',
        group: 'Actions',
        icon: RefreshCw,
        keywords: ['infrastructure', 'reload'],
        shortcut: 'r',
        when: () => Boolean(instanceId),
        run: () => refresh(),
      },
    ],
    [instanceId, targetUnavailable, target?.vm.state, prepare, refresh],
  )
  useRegisterCommands(commands)

  // ── Keyboard: R refreshes state (scope: this tool) ─────────────────────────
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() !== 'r' || e.metaKey || e.ctrlKey || e.altKey) return
      if (isEditableTarget(e.target)) return
      infra.refresh()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [infra.refresh])

  // ── Loading / error / blocked presentations ────────────────────────────────
  if (loading) {
    return (
      <div className="flex h-full flex-col bg-app" data-testid="deployments-loading">
        <WorkbenchToolHeader name="Deployments" icon={Server} />
        <SkeletonRows rows={7} className="p-4" />
      </div>
    )
  }

  if (loadError) {
    return (
      <div className="flex h-full flex-col bg-app">
        <WorkbenchToolHeader name="Deployments" icon={Server} />
        <ErrorState
          title="Could not load infrastructure state"
          error={loadError}
          preservedNote="Nothing was changed."
          onRetry={infra.refresh}
        />
      </div>
    )
  }

  const dominant = target ? dominantTargetPresentation(target) : null
  const primaryAction = !targetUnavailable && target ? (
    target.vm.state === 'not_defined' ? (
      <Button size="sm" onClick={() => void prepare('create_or_update')} disabled={busy || running}>
        <Server aria-hidden="true" />
        Create VM
      </Button>
    ) : target.vm.state === 'stopped' ? (
      <Button size="sm" onClick={() => void prepare('start')} disabled={busy || running}>
        <Play aria-hidden="true" />
        Start VM
      </Button>
    ) : target.vm.state === 'running' ? (
      <Button size="sm" variant="outline" onClick={() => void prepare('stop')} disabled={busy || running}>
        <Square aria-hidden="true" />
        Stop VM
      </Button>
    ) : null
  ) : null

  return (
    <div className="flex h-full flex-col bg-app" data-testid="deployments-tool">
      {/* Route-smoke compat: src/shell/__tests__/routes.test.tsx still pins the
          stub testid; the shell owner updates it to "deployments-tool". */}
      <span hidden data-testid="deployments-stub" aria-hidden="true" />
      <div aria-live="polite" className="sr-only">
        {announcement}
      </div>
      <WorkbenchToolHeader
        name="Deployments"
        icon={Server}
        state={dominant ? <StatusBadgeFrom presentation={dominant} /> : null}
        primaryAction={primaryAction}
      />

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto flex max-w-5xl flex-col gap-3 p-3">
          {infra.refreshFailed ? (
            <InlineNotice
              tone="attention"
              title="Refresh failed"
              action={
                <Button size="sm" variant="ghost" onClick={infra.refresh}>
                  Retry
                </Button>
              }
            >
              {infra.lastRefreshAt ? (
                <>
                  Last updated <TimeAgo date={infra.lastRefreshAt} /> — showing the last verified state.
                </>
              ) : (
                'Showing the last verified state.'
              )}
            </InlineNotice>
          ) : null}

          {targetUnavailable ? (
            <UnavailableState
              reason={infra.unavailableReason}
              repository={target?.repository ?? instance?.repository ?? null}
              onRefresh={infra.refresh}
              onReviewConfiguration={() => void navigate(`/app/${instanceId}/settings`)}
            />
          ) : target ? (
            <>
              <IdentityStrip target={target} />

              <StateRow
                target={target}
                authorization={infra.authorization}
                lastRefreshAt={infra.lastRefreshAt}
                lastHealthReceipt={infra.receipts.find((r) => r.eventKind === 'infrastructure.health_check')}
                infoFact={infoFact}
                onInfoFact={setInfoFact}
              />

              <ActionsRow
                target={target}
                busy={busy}
                running={running}
                isMobile={isMobile}
                menuOpen={menuOpen}
                onMenuOpen={setMenuOpen}
                onOperation={startOperation}
              />

              {opError ? (
                <InlineNotice tone="danger" title="Operation failed" className="whitespace-pre-wrap">
                  {opError}
                </InlineNotice>
              ) : null}

              {activePlan ? (
                <PlanCard
                  instanceId={instanceId}
                  plan={activePlan}
                  target={target}
                  run={infra.run}
                  running={running}
                  onRun={(plan) => void infra.runPlan(plan)}
                  onDiscard={infra.dismissPlan}
                />
              ) : (
                <p className="rounded-md border border-dashed border-border px-3 py-2 text-xs text-foreground-tertiary">
                  No active plan. Prepare one from the operations above — preparing never runs anything.
                </p>
              )}

              <div ref={authorizationRef} tabIndex={-1} className="outline-none">
                <AuthorizationCard
                  instanceId={instanceId}
                  target={target}
                  grant={infra.authorization}
                  busy={busy}
                  canRevoke={getClient().infrastructure.canRevokeAuthorization}
                  onPropose={infra.proposeAuthorization}
                  onActivate={infra.activateAuthorization}
                  onRevoke={infra.revokeAuthorization}
                />
              </div>

              <OperationHistory
                receipts={infra.receipts}
                onOpen={(receiptId) => void navigate(`/app/${instanceId}/workbench/receipts/${receiptId}`)}
              />
            </>
          ) : null}
        </div>
      </div>

      {/* Destruction always starts with typed confirmation of the exact target
          name, then still needs its own approval before it can run. */}
      <ConfirmDialog
        open={destroyConfirm}
        onOpenChange={setDestroyConfirm}
        title="Prepare VM destruction?"
        description="This prepares a destruction plan for review. Running it still requires a separate exact approval."
        target={target?.name}
        effect="If approved and run, the virtual machine and its virtual disk are deleted."
        reversibility="Not reversible once run — the virtual disk will be deleted."
        confirmLabel="Prepare destruction plan"
        destructive
        requireTypedConfirmation={target?.name ?? ''}
        onConfirm={() => prepare('destroy')}
      />
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// The ONE blocked state (infrastructure.md "The unavailable state" — binding)
// ─────────────────────────────────────────────────────────────────────────────

function UnavailableState({
  reason,
  repository,
  onRefresh,
  onReviewConfiguration,
}: {
  reason?: string
  repository: { name: string; branch: string; revision: string; clean: boolean } | null
  onRefresh: () => void
  onReviewConfiguration: () => void
}) {
  return (
    <div className="flex flex-col gap-3" data-testid="deployments-unavailable">
      {/* The identity strip still renders what IS known (repository facts). */}
      {repository ? (
        <div className="rounded-md border border-border bg-surface px-3 py-2">
          <p className="text-xs font-medium text-foreground-secondary">Repository</p>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="inline-flex items-center gap-1 text-sm text-foreground">
              <FolderGit2 className="size-4 text-foreground-secondary" aria-hidden="true" />
              {repository.name}
            </span>
            <span className="inline-flex items-center gap-1 text-xs text-foreground-secondary">
              <GitBranch className="size-3.5" aria-hidden="true" />
              {repository.branch}
            </span>
            <span className="tnum font-mono text-xs text-foreground-tertiary">{repository.revision.slice(0, 10)}</span>
            <StatusDotFrom presentation={repositoryCleanPresentation(repository.clean)} />
          </div>
        </div>
      ) : null}

      <div
        className="flex flex-col items-center gap-2 rounded-md border border-status-blocked-border bg-status-blocked-bg px-6 py-10 text-center"
        role="status"
      >
        <Unplug className="size-5 text-status-blocked" aria-hidden="true" />
        <h2 className="text-lg text-foreground">Target unavailable</h2>
        <p className="max-w-md text-sm text-foreground-secondary">
          {reason ?? "StatePort can't verify a virtual-machine target for this application."}
        </p>
        <p className="max-w-md text-xs text-foreground-tertiary">
          Grant, plan, and operation controls are hidden until a target can be verified.
        </p>
        <div className="mt-2 flex items-center gap-2">
          <Button size="sm" onClick={onRefresh} data-testid="unavailable-refresh">
            <RefreshCw aria-hidden="true" />
            Refresh
          </Button>
          <Button size="sm" variant="ghost" onClick={onReviewConfiguration} data-testid="unavailable-review-config">
            Review configuration
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity strip — repository + target, side by side
// ─────────────────────────────────────────────────────────────────────────────

function IdentityStrip({ target }: { target: import('@/client').InfrastructureTarget }) {
  const repo = target.repository
  return (
    <div className="grid gap-2 sm:grid-cols-2" data-testid="identity-strip">
      <div className="rounded-md border border-border bg-surface px-3 py-2">
        <div className="flex items-center justify-between gap-2">
          <p className="text-xs font-medium text-foreground-secondary">Repository</p>
          <StatusDotFrom presentation={repositoryPresentation(target)} />
        </div>
        <div className="mt-1 flex items-center gap-2">
          <FolderGit2 className="size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
          <span className="truncate text-sm font-medium text-foreground">{repo.name}</span>
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="inline-flex items-center gap-1 text-xs text-foreground-secondary">
            <GitBranch className="size-3.5" aria-hidden="true" />
            {repo.branch}
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="tnum font-mono text-xs text-foreground-tertiary">{repo.revision.slice(0, 10)}</span>
            <CopyButton text={repo.revision} label="Copy revision" />
          </span>
        </div>
      </div>

      <div className="rounded-md border border-border bg-surface px-3 py-2">
        <div className="flex items-center justify-between gap-2">
          <p className="text-xs font-medium text-foreground-secondary">Target</p>
          <StatusDotFrom presentation={dominantTargetPresentation(target)} />
        </div>
        <div className="mt-1 flex items-center gap-2">
          <MonitorCog className="size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
          <span className="truncate text-sm font-medium text-foreground">{target.name}</span>
          <span className="text-xs text-foreground-tertiary">Local VM</span>
        </div>
        <div className="mt-1 flex items-center gap-1">
          <span className="tnum font-mono text-xs text-foreground-tertiary">{target.id}</span>
          <CopyButton text={target.id} label="Copy target ID" />
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// State row — the distinct truths as labeled mini-facts
// ─────────────────────────────────────────────────────────────────────────────

interface FactDef {
  id: string
  label: string
  presentation: SemanticPresentation
  asOf?: string
  asOfLabel?: string
  explanation: string
}

function StateRow({
  target,
  authorization,
  lastRefreshAt,
  lastHealthReceipt,
  infoFact,
  onInfoFact,
}: {
  target: import('@/client').InfrastructureTarget
  authorization: import('@/client').AuthorizationGrant | null
  lastRefreshAt: string | null
  lastHealthReceipt: import('@/client').Receipt | undefined
  infoFact: string | null
  onInfoFact: (fact: string | null) => void
}) {
  const authzPresentation: SemanticPresentation = !authorization
    ? { state: 'neutral', label: 'None', icon: ShieldCheck }
    : authorization.status === 'active'
      ? { state: 'success', label: 'Active', icon: ShieldCheck }
      : authorization.status === 'proposed'
        ? { state: 'waiting', label: 'Proposed', icon: ShieldCheck }
        : { state: 'neutral', label: authorization.status === 'expired' ? 'Expired' : 'Revoked', icon: ShieldCheck }

  const facts: FactDef[] = [
    {
      id: 'vm',
      label: 'VM power',
      presentation: vmPowerPresentation(target),
      asOf: target.vm.since,
      asOfLabel: 'since',
      explanation:
        target.vm.state === 'running' && target.health.state !== 'healthy'
          ? 'The VM is powered on, but power is not health — run health checks before treating it as healthy.'
          : target.vm.state === 'not_defined'
            ? 'The governed target is registered, but the virtual machine has not been created.'
          : target.vm.state === 'stopped'
            ? 'The virtual machine is stopped. Stopped is neutral, not a failure.'
            : 'The current power state of the virtual machine.',
    },
    {
      id: 'ssh',
      label: 'SSH',
      presentation: sshPresentation(target),
      explanation:
        target.ssh.state === 'unavailable_vm_not_defined'
          ? 'SSH is unavailable because the VM has not been created.'
          : target.ssh.state === 'unavailable_vm_stopped'
          ? 'SSH is unavailable because the VM is stopped — start the VM to make SSH ready.'
          : target.ssh.state === 'failed'
            ? 'SSH failed while the VM is running. Check the VM console or restart the VM.'
            : target.ssh.detail ?? 'Whether StatePort can reach the VM over SSH.',
    },
    {
      id: 'health',
      label: 'Health',
      presentation: healthPresentation(target),
      asOf: target.health.checkedAt,
      asOfLabel: 'checked',
      explanation:
        target.health.state === 'not_checked'
          ? target.vm.state === 'running'
            ? 'Health checks have not run since the VM started. Running is not the same as healthy.'
            : 'Health checks run against a running VM — start the VM first.'
          : (target.health.detail ?? 'The result of the last health check run.'),
    },
    {
      id: 'authz',
      label: 'Authorization',
      presentation: authzPresentation,
      asOf: authorization?.status === 'active' ? authorization.expiresAt : undefined,
      asOfLabel: 'until',
      explanation: !authorization
        ? 'No daily-driver authorization. Routine operations each need their own approval.'
        : authorization.status === 'active'
          ? 'Routine operations are covered by the daily-driver authorization until it expires.'
          : authorization.status === 'proposed'
            ? 'A daily-driver authorization is proposed and waiting for its grant approval.'
            : 'The daily-driver authorization is no longer in effect.',
    },
  ]

  return (
    <section aria-label="Target state" data-testid="state-row">
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        {facts.map((fact) => (
          <div key={fact.id} className="rounded-md border border-border bg-surface px-2.5 py-2" data-testid={`fact-${fact.id}`} data-state={fact.presentation.state}>
            <div className="flex items-center justify-between gap-1">
              <p className="text-xs font-medium text-foreground-secondary">{fact.label}</p>
              <Tooltip content="Why this state?">
                <button
                  type="button"
                  aria-label={`Why: ${fact.label}`}
                  aria-expanded={infoFact === fact.id}
                  onClick={() => onInfoFact(infoFact === fact.id ? null : fact.id)}
                  className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-tertiary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                >
                  <Info className="size-3.5" aria-hidden="true" />
                </button>
              </Tooltip>
            </div>
            <div className="mt-0.5">
              <StatusDotFrom presentation={fact.presentation} />
            </div>
            {fact.asOf ? (
              <p className="mt-0.5 text-xs text-foreground-tertiary">
                {fact.asOfLabel} <TimeAgo date={fact.asOf} />
              </p>
            ) : null}
            {fact.id === 'health' && lastHealthReceipt ? (
              <p className="mt-0.5 truncate text-xs text-foreground-tertiary">
                last success <TimeAgo date={lastHealthReceipt.createdAt} />
              </p>
            ) : null}
          </div>
        ))}
      </div>
      {infoFact ? (
        <div data-testid="fact-explanation" className="mt-2">
          <InlineNotice tone="informational">
            {facts.find((f) => f.id === infoFact)?.explanation}
          </InlineNotice>
        </div>
      ) : null}
      {lastRefreshAt ? (
        <p className="mt-1 text-right text-xs text-foreground-tertiary">
          state as of <TimeAgo date={lastRefreshAt} />
        </p>
      ) : null}
    </section>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Actions row — context-appropriate operations, never the full disabled catalog
// ─────────────────────────────────────────────────────────────────────────────

function ActionsRow({
  target,
  busy,
  running,
  isMobile,
  menuOpen,
  onMenuOpen,
  onOperation,
}: {
  target: import('@/client').InfrastructureTarget
  busy: boolean
  running: boolean
  isMobile: boolean
  menuOpen: boolean
  onMenuOpen: (open: boolean) => void
  onOperation: (meta: OperationMeta) => void
}) {
  const vmRunning = target.vm.state === 'running'
  const vmStopped = target.vm.state === 'stopped'
  const vmNotDefined = target.vm.state === 'not_defined'
  const transitioning = target.vm.state === 'starting' || target.vm.state === 'stopping'
  const disabled = busy || running

  // Context-appropriate catalog (health checks hidden until the VM runs).
  const inspect = [OPERATION_META.validate, OPERATION_META.observe]
  if (vmRunning) inspect.push(OPERATION_META.health_check)
  const operate: OperationMeta[] = []
  if (vmNotDefined) operate.push(OPERATION_META.create_or_update)
  if (vmStopped || vmRunning) operate.push(OPERATION_META.create_or_update)
  if (vmStopped) operate.push(OPERATION_META.start)
  if (vmRunning) operate.push(OPERATION_META.stop, OPERATION_META.restart)

  const menu = (
    <DropdownMenu open={menuOpen} onOpenChange={onMenuOpen}>
      <Tooltip content="All operations — each prepares a plan for review first">
        <DropdownMenuTrigger
          aria-label="More operations"
          className="inline-flex min-h-11 items-center gap-1 rounded-sm border border-border bg-surface px-2 text-sm text-foreground transition-colors duration-instant hover:bg-hover md:min-h-8"
          data-testid="operations-menu-trigger"
        >
          <MoreHorizontal className="size-4" aria-hidden="true" />
          {isMobile ? 'More actions' : null}
        </DropdownMenuTrigger>
      </Tooltip>
      <DropdownMenuContent align="start" className="w-64 bg-surface" data-testid="operations-menu">
        <DropdownMenuLabel>Inspect — read-only, no approval</DropdownMenuLabel>
        {inspect.map((meta) => (
          <DropdownMenuItem key={meta.operation} disabled={disabled} onSelect={() => onOperation(meta)}>
            <meta.icon className="size-4" aria-hidden="true" />
            <span className="flex-1">{meta.label}</span>
          </DropdownMenuItem>
        ))}
        {operate.length > 0 ? (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuLabel>Operate — prepares a plan</DropdownMenuLabel>
            {operate.map((meta) => (
              <DropdownMenuItem key={meta.operation} disabled={disabled} onSelect={() => onOperation(meta)}>
                <meta.icon className="size-4" aria-hidden="true" />
                <span className="flex-1">{meta.label}</span>
              </DropdownMenuItem>
            ))}
          </>
        ) : null}
        <DropdownMenuSeparator />
        <DropdownMenuLabel className="text-status-danger">Destructive</DropdownMenuLabel>
        <DropdownMenuItem
          disabled={disabled || transitioning}
          onSelect={() => onOperation(OPERATION_META.destroy)}
          className="text-status-danger"
          data-testid="prepare-destruction"
        >
          <OPERATION_META.destroy.icon className="size-4" aria-hidden="true" />
          <span className="flex-1">{OPERATION_META.destroy.label}</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )

  const opButton = (meta: OperationMeta, primary = false) => (
    <Button
      key={meta.operation}
      size="sm"
      variant={primary ? 'default' : 'outline'}
      disabled={disabled}
      onClick={() => onOperation(meta)}
      data-testid={`op-${meta.operation}`}
    >
      <meta.icon aria-hidden="true" />
      {meta.label}
    </Button>
  )

  if (isMobile) {
    // Mobile: one primary action + "More actions" sheet (infrastructure.md).
    return (
      <div className="flex items-center gap-1.5" data-testid="actions-row">
        {vmNotDefined ? opButton(OPERATION_META.create_or_update, true) : null}
        {vmStopped ? opButton(OPERATION_META.start, true) : null}
        {vmRunning ? opButton(OPERATION_META.stop, true) : null}
        {menu}
      </div>
    )
  }

  return (
    <div className="flex flex-wrap items-center gap-1.5" data-testid="actions-row">
      <span className="text-xs font-medium text-foreground-tertiary">Inspect</span>
      {inspect.map((meta) => opButton(meta))}
      {operate.length > 0 ? (
        <>
          <span className="mx-1 h-4 w-px bg-border" aria-hidden="true" />
          <span className="text-xs font-medium text-foreground-tertiary">Operate</span>
          {operate.map((meta, i) => opButton(meta, i === 0 && (vmStopped || vmNotDefined)))}
        </>
      ) : null}
      <span className="mx-1 h-4 w-px bg-border" aria-hidden="true" />
      {menu}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Operation history — infrastructure-scoped receipts
// ─────────────────────────────────────────────────────────────────────────────

function OperationHistory({
  receipts,
  onOpen,
}: {
  receipts: import('@/client').Receipt[]
  onOpen: (receiptId: string) => void
}) {
  const scoped = receipts.filter(
    (r) => r.eventKind.startsWith('infrastructure.') || r.eventKind.startsWith('authorization.') || r.eventKind.startsWith('approval.'),
  )
  if (scoped.length === 0) return null
  return (
    <section aria-label="Operation history" data-testid="operation-history" className="rounded-md border border-border bg-surface">
      <p className="border-b border-border px-3 py-2 text-xs font-medium text-foreground-secondary">
        Operation history
      </p>
      <ul className="divide-y divide-border">
        {scoped.slice(0, 10).map((receipt) => (
          <li key={receipt.id}>
            <button
              type="button"
              onClick={() => onOpen(receipt.id)}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-left transition-colors duration-instant hover:bg-hover"
            >
              <span className="min-w-0 flex-1 truncate text-sm text-foreground">{receipt.actionName}</span>
              <StatusBadgeFrom presentation={receiptResultPresentation(receipt.result)} />
              <span className="text-xs capitalize text-foreground-tertiary">{receipt.actor}</span>
              <TimeAgo date={receipt.createdAt} />
            </button>
          </li>
        ))}
      </ul>
    </section>
  )
}
