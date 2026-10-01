/**
 * FactsStrip — the operational summary of the App overview: ONE hairline-boxed
 * row of 3–5 facts (last activity · current view · branch/source when present ·
 * backup state · last receipt). Facts, not stat cards; two-column grid on
 * mobile. Backup state uses the recovery semantic mapping (backup-due IS the
 * attention state — it is not restated anywhere else on the page).
 */
import { FileClock, GitBranch } from 'lucide-react'
import { Link } from 'react-router-dom'

import type { ApplicationInstance, Receipt } from '@/client'
import type { SemanticPresentation } from '@/semantic'
import { TimeAgo, Tooltip } from '@/components'
import { cn } from '@/lib/utils'

import { RECOVERY_PRESENTATION } from '@/features/applications/lib/recoveryPresentation'

export interface FactsStripProps {
  instance: ApplicationInstance
  /** Label of the view Continue resumes (e.g. "Files", "Conversation"). */
  currentViewLabel: string
  lastReceipt: Receipt | null
  /** Receipt deep-links are application-native and do not require Workbench. */
  hasReceipts: boolean
}

function Fact({ label, children, testId }: { label: string; children: React.ReactNode; testId?: string }) {
  return (
    <div className="flex min-w-0 items-center gap-1.5 text-xs" data-testid={testId}>
      <span className="shrink-0 text-foreground-tertiary">{label}</span>
      {children}
    </div>
  )
}

const STATE_TEXT: Record<string, string> = {
  success: 'text-status-success',
  neutral: 'text-foreground-secondary',
  attention: 'text-status-attention',
  waiting: 'text-status-waiting',
  blocked: 'text-status-blocked',
  danger: 'text-status-danger',
  informational: 'text-status-informational',
}

export function FactsStrip({ instance, currentViewLabel, lastReceipt, hasReceipts }: FactsStripProps) {
  const backup: SemanticPresentation = RECOVERY_PRESENTATION[instance.recovery.state]
  const BackupIcon = backup.icon
  const lastBackup = instance.recovery.lastBackupAt

  return (
    <div
      className="grid grid-cols-2 gap-x-4 gap-y-2 rounded-md border border-border bg-surface px-3 py-2 md:flex md:flex-wrap md:items-center md:gap-y-1"
      data-testid="facts-strip"
    >
      <Fact label="Last activity">
        <TimeAgo date={instance.lastOpenedAt ?? instance.createdAt} className="text-foreground" />
      </Fact>
      <Fact label="Current view">
        <span className="truncate text-foreground">{currentViewLabel}</span>
      </Fact>
      {instance.repository ? (
        <Fact label="Branch">
          <Tooltip content={instance.repository.clean ? 'Working tree clean' : 'Uncommitted changes'}>
            <span className="inline-flex min-w-0 items-center gap-1">
              <GitBranch className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
              <span className="truncate font-mono text-foreground">{instance.repository.branch}</span>
              <span className={cn('shrink-0', instance.repository.clean ? 'text-foreground-tertiary' : 'text-status-attention')}>
                {instance.repository.clean ? '· clean' : '· uncommitted changes'}
              </span>
            </span>
          </Tooltip>
        </Fact>
      ) : null}
      <Fact label="Backup" testId="fact-backup">
        {backup.state === 'attention' ? (
          <Tooltip content="No current verified backup. Run a backup from the Recovery section below to make this application's state recoverable.">
            <span className={cn('inline-flex items-center gap-1 font-medium', STATE_TEXT[backup.state])} data-state={backup.state}>
              <BackupIcon className={cn('size-3.5', backup.spin && 'icon-spin')} aria-hidden="true" />
              {backup.label}
            </span>
          </Tooltip>
        ) : (
          <span className={cn('inline-flex items-center gap-1 font-medium', STATE_TEXT[backup.state])} data-state={backup.state}>
            <BackupIcon className={cn('size-3.5', backup.spin && 'icon-spin')} aria-hidden="true" />
            {backup.label}
          </span>
        )}
        {lastBackup ? (
          <span className="text-foreground-tertiary">
            · <TimeAgo date={lastBackup} />
          </span>
        ) : null}
      </Fact>
      {lastReceipt ? (
        <Fact label="Last receipt" testId="fact-receipt">
          {hasReceipts ? (
            <Link
              to={`/app/${instance.id}/receipts/${lastReceipt.id}`}
              className="inline-flex min-w-0 items-center gap-1 text-accent hover:underline"
            >
              <FileClock className="size-3.5 shrink-0" aria-hidden="true" />
              <span className="truncate">{lastReceipt.actionName}</span>
              <TimeAgo date={lastReceipt.createdAt} className="shrink-0" />
            </Link>
          ) : (
            <span className="inline-flex min-w-0 items-center gap-1 text-foreground">
              <FileClock className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
              <span className="truncate">{lastReceipt.actionName}</span>
              <TimeAgo date={lastReceipt.createdAt} className="shrink-0" />
            </span>
          )}
        </Fact>
      ) : null}
      <span className="sr-only">{`Backup state: ${backup.label}.`}</span>
    </div>
  )
}
