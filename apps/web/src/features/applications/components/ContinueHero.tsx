/**
 * ContinueHero — the dominant resume row of the Applications home
 * (applications.md §Section 1): the last active workspace with the context it
 * will restore, last activity, an inline OperationStateLabel when a
 * long-running operation is active, and the primary Continue button.
 */
import { Play } from 'lucide-react'

import type { ApplicationInstance, OperationRecord } from '@/client'
import { OperationStateLabel, TimeAgo } from '@/components'
import { Button } from '@/components/ui/button'
import { InstanceGlyphTile } from '@/shell/appIcon'

import type { ResumeTarget } from '../lib/continuity'

export type { ResumeTarget } from '../lib/continuity'

export function ContinueHero({
  instance,
  liveOperation,
  target,
  onContinue,
}: {
  instance: ApplicationInstance
  liveOperation?: OperationRecord
  target: ResumeTarget
  onContinue: () => void
}) {
  return (
    <div
      className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border border-border bg-surface p-3 max-md:p-2.5"
      data-testid="continue-hero"
    >
      <InstanceGlyphTile instance={instance} className="size-9 rounded-md max-md:size-8" />
      <div className="min-w-0 flex-1 basis-48">
        <p className="truncate text-lg text-foreground">{instance.name}</p>
        <p className="truncate text-xs text-foreground-secondary">
          {instance.packageDisplayName} · {target.viewLabel}
        </p>
        {target.contextLabel ? (
          <p className="truncate text-xs text-foreground-tertiary">{target.contextLabel}</p>
        ) : null}
      </div>
      {liveOperation ? (
        <OperationStateLabel state={liveOperation.state} startedAt={liveOperation.startedAt} className="shrink-0" />
      ) : null}
      <TimeAgo date={instance.lastOpenedAt ?? instance.createdAt} className="shrink-0" />
      <Button onClick={onContinue} aria-label={`Continue in ${instance.name}`} className="min-h-10 max-md:w-full md:min-h-9">
        <Play aria-hidden="true" />
        Continue
      </Button>
    </div>
  )
}
