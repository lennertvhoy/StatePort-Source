/**
 * Service status popover (design.md §9.4) — the honest diagnostic surface for
 * the local service: what failed, last successful contact, and recovery
 * actions (Retry connection / Open diagnostics / Review endpoint). Never a
 * red blob with no explanation.
 */
import type { ReactNode } from 'react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { TimeAgo } from '@/components'
import { StatusDot } from '@/components/StatusDot'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { localServicePresentation } from '@/semantic'
import { useSessionStore } from '@/state'

import { reconnectService } from './data'

export function ServiceStatusPopover({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const [retrying, setRetrying] = useState(false)
  const status = useSessionStore((s) => s.serviceStatus)
  const navigate = useNavigate()
  const presentation = localServicePresentation(status?.state ?? 'unknown')
  const runtime = status?.state === 'connected' || status?.state === 'degraded' ? status.runtime : undefined

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>{children}</PopoverTrigger>
      <PopoverContent side="right" align="end" sideOffset={8} className="w-80 max-w-[calc(100vw-1rem)] bg-surface p-0" data-testid="service-status-popover">
        <div className="flex items-center gap-2 border-b border-border px-3 py-2">
          <presentation.icon className="size-4 text-foreground-secondary" aria-hidden="true" />
          <span className="text-sm font-medium text-foreground">Local service — {presentation.label}</span>
        </div>
        <div className="flex flex-col gap-2 px-3 py-3 text-sm">
          {status?.detail ? <p className="text-foreground-secondary">{status.detail}</p> : null}
          {runtime ? (
            <div className="flex flex-col gap-1 rounded-sm border border-border bg-surface-secondary/50 px-2 py-2">
              <div className="flex items-center gap-2">
                <StatusDot
                  state={runtime.status === 'available' ? 'success' : 'blocked'}
                  label={runtime.status === 'available' ? 'Execution runtime available' : 'Execution runtime unavailable'}
                />
                <span className="text-xs font-medium text-foreground">Execution runtime</span>
              </div>
              {runtime.detail ? <p className="text-xs text-foreground-secondary">{runtime.detail}</p> : null}
              {runtime.workerExecutionEnabled === false ? (
                <p className="text-xs text-foreground-secondary">Worker container executor is disabled.</p>
              ) : null}
              {runtime.socketPath ? (
                <p className="tnum truncate font-mono text-[11px] text-foreground-secondary">{runtime.socketPath}</p>
              ) : null}
            </div>
          ) : null}
          <dl className="flex flex-col gap-1 text-xs">
            {status?.endpoint ? (
              <div className="flex items-baseline gap-2">
                <dt className="shrink-0 text-foreground-secondary">Endpoint</dt>
                <dd className="tnum truncate font-mono text-foreground">{status.endpoint}</dd>
              </div>
            ) : null}
            {status?.version ? (
              <div className="flex items-baseline gap-2">
                <dt className="shrink-0 text-foreground-secondary">Version</dt>
                <dd className="tnum font-mono text-foreground">{status.version}</dd>
              </div>
            ) : null}
            {status?.lastContactAt ? (
              <div className="flex items-baseline gap-2">
                <dt className="shrink-0 text-foreground-secondary">Last contact</dt>
                <dd className="text-foreground">
                  <TimeAgo date={status.lastContactAt} />
                </dd>
              </div>
            ) : null}
          </dl>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              disabled={retrying}
              onClick={async () => {
                setRetrying(true)
                try {
                  await reconnectService()
                } finally {
                  setRetrying(false)
                }
              }}
            >
              {retrying ? 'Retrying…' : 'Retry connection'}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setOpen(false)
                void navigate('/settings/advanced')
              }}
            >
              Open diagnostics
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setOpen(false)
                void navigate('/platform')
              }}
            >
              Review readiness
            </Button>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  )
}
