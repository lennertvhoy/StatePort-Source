/**
 * PasteGuardDialog — the paste safety interstitial (terminal.md, brief
 * §Terminal paste safety). Shows the exact pasted text, the line count, and
 * any matched destructive patterns (highlighted), then offers:
 *   Insert without running (default-focused) · Insert and run (explicit) · Cancel.
 * Destructive pastes get the stronger danger variant; "Insert and run" is
 * always an explicit, separate choice — never the default.
 */
import { ShieldAlert, TriangleAlert } from 'lucide-react'
import { useRef, useState } from 'react'

import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

import type { PasteAnalysis } from './pasteGuard'
import { highlightLine } from './pasteGuard'

export interface PasteGuardDialogProps {
  analysis: PasteAnalysis | null
  onResolve: (resolution: 'insert' | 'insert_run' | 'cancel') => void
}

const MAX_PREVIEW_LINES = 12

export function PasteGuardDialog({ analysis, onResolve }: PasteGuardDialogProps) {
  const [busy, setBusy] = useState(false)
  // Reset the busy flag when a new analysis opens (adjust-during-render).
  const [previousAnalysis, setPreviousAnalysis] = useState(analysis)
  if (analysis !== previousAnalysis) {
    setPreviousAnalysis(analysis)
    setBusy(false)
  }
  const insertButtonRef = useRef<HTMLButtonElement>(null)

  const destructive = analysis?.destructive ?? false

  return (
    <AlertDialog open={analysis !== null} onOpenChange={(open) => !open && onResolve('cancel')}>
      <AlertDialogContent
        data-testid="paste-guard-dialog"
        className="bg-surface"
        onOpenAutoFocus={(event) => {
          // "Insert without running" is the default-focused action (design).
          event.preventDefault()
          insertButtonRef.current?.focus()
        }}
      >
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2 text-xl">
            {destructive ? (
              <ShieldAlert className="size-5 text-status-danger" aria-hidden="true" />
            ) : (
              <TriangleAlert className="size-5 text-status-attention" aria-hidden="true" />
            )}
            {destructive ? 'Potentially destructive paste' : 'Paste multiple lines?'}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {destructive
              ? 'The pasted text contains commands that can destroy data or change the system. Review every line before running anything.'
              : `You are pasting ${analysis?.lineCount ?? 0} lines into the terminal. Review the text — running it is always your explicit choice.`}
          </AlertDialogDescription>
        </AlertDialogHeader>

        {analysis ? (
          <div className="flex min-w-0 flex-col gap-2">
            <dl className="flex items-baseline gap-2 text-sm">
              <dt className="shrink-0 text-xs font-medium text-foreground-secondary">Lines</dt>
              <dd className="tnum font-mono text-xs text-foreground">{analysis.lineCount}</dd>
            </dl>
            {analysis.risks.length > 0 ? (
              <ul className="flex flex-col gap-1" data-testid="paste-guard-risks">
                {analysis.risks.map((risk) => (
                  <li key={risk.id} className="flex items-center gap-1.5 text-xs text-status-danger">
                    <ShieldAlert className="size-3.5 shrink-0" aria-hidden="true" />
                    {risk.label}
                  </li>
                ))}
              </ul>
            ) : null}
            <pre
              className="max-h-56 overflow-auto rounded-sm border border-border bg-sunken p-2 font-mono text-xs whitespace-pre-wrap break-all text-foreground"
              data-testid="paste-guard-preview"
            >
              {analysis.lines.slice(0, MAX_PREVIEW_LINES).map((line, i) => (
                <span key={i}>
                  {highlightLine(line, analysis.risks).map((segment, j) =>
                    segment.risky ? (
                      <mark key={j} className="bg-status-danger-bg text-status-danger">
                        {segment.text}
                      </mark>
                    ) : (
                      <span key={j}>{segment.text}</span>
                    ),
                  )}
                  {'\n'}
                </span>
              ))}
              {analysis.lineCount > MAX_PREVIEW_LINES ? (
                <span className="text-foreground-tertiary">… {analysis.lineCount - MAX_PREVIEW_LINES} more lines</span>
              ) : null}
            </pre>
          </div>
        ) : null}

        <AlertDialogFooter className={cn('sm:justify-between')}>
          <AlertDialogCancel disabled={busy} data-testid="paste-guard-cancel">
            Cancel
          </AlertDialogCancel>
          <div className="flex flex-col-reverse gap-2 sm:flex-row">
            <Button
              variant={destructive ? 'destructive' : 'outline'}
              disabled={busy}
              data-testid="paste-guard-insert-run"
              onClick={() => {
                setBusy(true)
                onResolve('insert_run')
              }}
            >
              Insert and run
            </Button>
            <Button
              ref={insertButtonRef}
              disabled={busy}
              data-testid="paste-guard-insert"
              onClick={() => {
                setBusy(true)
                onResolve('insert')
              }}
            >
              Insert without running
            </Button>
          </div>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
