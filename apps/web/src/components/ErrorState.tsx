/**
 * ErrorState (design.md §14) — what failed (plain language), a preserved-state
 * note when relevant, a primary recovery action (Retry/Reload), a secondary
 * (Open diagnostics / Copy technical details), and a collapsible technical
 * detail block (mono). Never blames the user; never fabricates fallback data.
 */
import { CircleX, RotateCcw, Stethoscope } from 'lucide-react'
import { useMemo } from 'react'

import { ClientError } from '@/client'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'

import { CopyButton } from './CopyButton'
import { Disclosure } from './Disclosure'

export interface ErrorStateProps {
  /** Plain-language statement of what failed. */
  title?: string
  /** The failure — Error, ClientError, or a plain message. */
  error?: unknown
  /** Extra context sentence (what is preserved / what was not done). */
  preservedNote?: string
  onRetry?: () => void
  retryLabel?: string
  onOpenDiagnostics?: () => void
  className?: string
}

function describe(error: unknown): { message: string; detail: string } {
  if (error instanceof ClientError) {
    const detail = [
      `kind: ${error.kind}`,
      error.status !== undefined ? `status: ${error.status}` : null,
      error.detail ? `detail: ${error.detail}` : null,
      error.stack ?? null,
    ]
      .filter(Boolean)
      .join('\n')
    return { message: error.message, detail }
  }
  if (error instanceof Error) return { message: error.message, detail: error.stack ?? error.message }
  return { message: typeof error === 'string' ? error : 'Something went wrong.', detail: String(error) }
}

export function ErrorState({
  title = 'Something went wrong',
  error,
  preservedNote,
  onRetry,
  retryLabel = 'Retry',
  onOpenDiagnostics,
  className,
}: ErrorStateProps) {
  const { message, detail } = useMemo(() => describe(error), [error])

  return (
    <div
      className={cn('flex h-full min-h-40 flex-col items-center justify-center gap-2 px-6 py-10 text-center', className)}
      data-testid="error-state"
      role="alert"
    >
      <CircleX className="size-5 text-status-danger" aria-hidden="true" />
      <h2 className="text-lg text-foreground">{title}</h2>
      <p className="max-w-md text-sm text-foreground-secondary">{message}</p>
      {preservedNote ? <p className="max-w-md text-xs text-foreground-tertiary">{preservedNote}</p> : null}
      <div className="mt-2 flex items-center gap-2">
        {onRetry ? (
          <Button size="sm" onClick={onRetry}>
            <RotateCcw aria-hidden="true" />
            {retryLabel}
          </Button>
        ) : null}
        {onOpenDiagnostics ? (
          <Button size="sm" variant="ghost" onClick={onOpenDiagnostics}>
            <Stethoscope aria-hidden="true" />
            Open diagnostics
          </Button>
        ) : null}
      </div>
      {detail ? (
        <div className="mt-3 w-full max-w-lg text-left">
          <Disclosure
            title="Technical details"
            className="rounded-md border border-border bg-surface-2"
            headerExtra={<CopyButton text={detail} label="Copy technical details" />}
          >
            <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words px-3 pb-3 font-mono text-xs text-foreground-secondary">
              {detail}
            </pre>
          </Disclosure>
        </div>
      ) : null}
    </div>
  )
}
