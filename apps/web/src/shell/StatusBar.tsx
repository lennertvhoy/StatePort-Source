/**
 * StatusBar (design.md §9.5) — 26 px (28 comfortable), workbench contexts
 * only. Items are 12 px/500 tabular, separated by hairline spacers; several
 * are buttons opening the related tool. Shows current context only; overflow
 * collapses progressively (never stacks to two rows).
 *
 * Context is provided by WorkbenchShell via WorkbenchStatusContext.
 */
import { Activity, FlaskConical, GitBranch, Server, ShieldQuestion } from 'lucide-react'
import type { ReactNode } from 'react'
import { useContext } from 'react'
import { Link } from 'react-router-dom'

import { OperationStateLabel, StatusDot, Tooltip } from '@/components'
import { cn } from '@/lib/utils'
import { localServicePresentation, terminalStatePresentation } from '@/semantic'
import { useSessionStore } from '@/state'

import { hasLiveOperation, usePendingApprovalsCount } from './data'
import { useShellUiStore } from './shellUi'
import { WorkbenchStatusContext } from './workbenchStatus'

function Item({
  children,
  to,
  onClick,
  label,
  className,
  testId,
}: {
  children?: ReactNode
  to?: string
  onClick?: () => void
  label?: string
  className?: string
  testId?: string
}) {
  const classes = cn(
    'tnum inline-flex h-full shrink-0 items-center gap-1.5 px-2 text-xs font-medium text-foreground-secondary',
    (to || onClick) && 'transition-colors duration-instant hover:bg-hover hover:text-foreground',
    className,
  )
  const inner = (
    <>
      {children}
      {label ? <span className="truncate">{label}</span> : null}
    </>
  )
  if (to) {
    return (
      <Link to={to} className={classes} data-testid={testId}>
        {inner}
      </Link>
    )
  }
  if (onClick) {
    return (
      <button type="button" onClick={onClick} className={classes} data-testid={testId}>
        {inner}
      </button>
    )
  }
  return (
    <span className={classes} data-testid={testId}>
      {inner}
    </span>
  )
}

function Spacer() {
  return <span className="h-3 w-px shrink-0 bg-border" aria-hidden="true" />
}

export function StatusBar() {
  const status = useContext(WorkbenchStatusContext)
  const serviceStatus = useSessionStore((s) => s.serviceStatus)
  const operations = useSessionStore((s) => s.operations)
  const buildInfo = useSessionStore((s) => s.buildInfo)
  const activeScenario = useSessionStore((s) => s.activeScenario)
  const toggleOperationCenter = useShellUiStore((s) => s.toggleOperationCenter)
  const { count: pendingApprovals, error: pendingApprovalsError } = usePendingApprovalsCount()

  if (!status) return null

  const service = localServicePresentation(serviceStatus?.state ?? 'unknown')
  const repo = status.instance.repository
  const terminal = status.terminalState ? terminalStatePresentation(status.terminalState) : null
  const liveOp = operations.find((o) => hasLiveOperation([o]))

  return (
    <footer
      className="flex h-statusbar shrink-0 items-center gap-0 overflow-hidden border-t border-border bg-surface"
      aria-label="Workbench status"
      data-testid="status-bar"
    >
      <div className="flex min-w-0 flex-1 items-center">
        <Item label={service.label} testId="status-service">
          <service.icon className="size-3" aria-hidden="true" />
        </Item>
        <Spacer />
        <Item label={status.instance.name} className="min-w-0" testId="status-instance" />
        {repo ? (
          <>
            <Spacer />
            <Tooltip content={`Branch ${repo.branch} · revision ${repo.revision.slice(0, 12)}`}>
              <Item
                label={repo.branch}
                to={status.deploymentsAvailable ? `/app/${status.instanceId}/workbench/deployments` : undefined}
                className="hidden min-w-0 max-w-44 md:inline-flex"
                testId="status-branch"
              >
                <GitBranch className="size-3 shrink-0" aria-hidden="true" />
              </Item>
            </Tooltip>
            {!repo.clean ? (
              <>
                <Spacer />
                <StatusDot state="attention" label="Uncommitted changes" showLabel={false} className="px-1" />
              </>
            ) : null}
          </>
        ) : null}
      </div>

      <div className="flex shrink-0 items-center">
        {import.meta.env.DEV && activeScenario ? (
          <>
            <Item className="text-status-waiting" testId="status-scenario">
              <FlaskConical className="size-3" aria-hidden="true" />
              <span className="font-mono">{activeScenario}</span>
            </Item>
            <Spacer />
          </>
        ) : null}
        {terminal && status.terminalAvailable ? (
          <>
            <Item
              label={terminal.label}
              to={`/app/${status.instanceId}/workbench/terminal`}
              className="hidden lg:inline-flex"
              testId="status-terminal"
            >
              <terminal.icon className={terminal.spin ? 'icon-spin size-3' : 'size-3'} aria-hidden="true" />
            </Item>
            <Spacer />
          </>
        ) : null}
        {status.targetName ? (
          <>
            <Item
              label={status.targetName}
              to={status.deploymentsAvailable ? `/app/${status.instanceId}/workbench/deployments` : undefined}
              className="hidden xl:inline-flex"
              testId="status-target"
            >
              <Server className="size-3" aria-hidden="true" />
            </Item>
            <Spacer />
          </>
        ) : null}
        <Item
          label={pendingApprovalsError ? 'Approvals unavailable' : `${pendingApprovals} pending`}
          to="/approvals"
          className="hidden md:inline-flex"
          testId="status-approvals"
        >
          <ShieldQuestion className="size-3" aria-hidden="true" />
        </Item>
        <Spacer />
        {liveOp ? (
          <>
            <Item onClick={toggleOperationCenter} className="min-w-0 max-w-52" testId="status-operation">
              <OperationStateLabel state={liveOp.state} label={liveOp.title} startedAt={liveOp.startedAt} className="text-xs" />
            </Item>
            <Spacer />
          </>
        ) : (
          <>
            <Item label="No active operation" onClick={toggleOperationCenter} className="hidden sm:inline-flex" testId="status-operation">
              <Activity className="size-3" aria-hidden="true" />
            </Item>
            <Spacer />
          </>
        )}
        {import.meta.env.DEV && buildInfo ? (
          <Item label={`${buildInfo.adapter} adapter`} testId="status-adapter" />
        ) : null}
      </div>
    </footer>
  )
}
