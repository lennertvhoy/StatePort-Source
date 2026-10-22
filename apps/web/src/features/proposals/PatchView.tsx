/**
 * PatchView — read-only unified diff viewer for a file proposal.
 *
 * Monospace rows with old/new line numbers; added and removed lines carry
 * both a colour and their `+`/`−` sign (never colour-only). Files with long
 * diffs start collapsed; every line of the exact patch stays reachable.
 */
import { ChevronDown, ChevronRight } from 'lucide-react'
import { useMemo, useState } from 'react'

import { StatusBadge } from '@/components'
import { cn } from '@/lib/utils'

import { patchLineCount, parseUnifiedDiff, type PatchFile, type PatchLine } from './unifiedDiff'
import { CHANGE_PRESENTATION, changeCountLabel } from './proposalModel'

/** Files whose diff has more rendered rows than this start collapsed. */
export const COLLAPSE_ROWS = 80

const LINE_CLASSES: Record<PatchLine['kind'], string> = {
  add: 'bg-status-success-bg text-status-success',
  del: 'bg-status-danger-bg text-status-danger',
  context: 'text-foreground-secondary',
  meta: 'italic text-foreground-tertiary',
}

const LINE_SIGN: Record<PatchLine['kind'], string> = { add: '+', del: '−', context: ' ', meta: ' ' }

function PatchRows({ file }: { file: PatchFile }) {
  return (
    <div className="overflow-x-auto font-mono text-xs leading-5" data-testid="patch-rows">
      {file.hunks.map((hunk, hunkIndex) => (
        <div key={hunkIndex}>
          <div className="whitespace-pre bg-sunken px-2 text-foreground-tertiary" data-kind="hunk">
            {hunk.header}
          </div>
          {hunk.lines.map((line, lineIndex) => (
            <div key={lineIndex} className={cn('flex min-w-max', LINE_CLASSES[line.kind])} data-kind={line.kind}>
              <span className="tnum w-10 shrink-0 select-none pr-1 text-right opacity-70" aria-hidden="true">
                {line.oldNumber ?? ''}
              </span>
              <span className="tnum w-10 shrink-0 select-none pr-1 text-right opacity-70" aria-hidden="true">
                {line.newNumber ?? ''}
              </span>
              <span className="w-4 shrink-0 select-none text-center" aria-hidden="true">
                {LINE_SIGN[line.kind]}
              </span>
              <span className="sr-only">
                {line.kind === 'add' ? 'Added: ' : line.kind === 'del' ? 'Removed: ' : ''}
              </span>
              <span className="whitespace-pre pr-3">{line.text}</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

function PatchFileSection({ file }: { file: PatchFile }) {
  const rows = patchLineCount(file)
  const long = rows > COLLAPSE_ROWS
  const [open, setOpen] = useState(!long)
  const change = CHANGE_PRESENTATION[file.change]
  const Chevron = open ? ChevronDown : ChevronRight
  const hasRows = file.hunks.length > 0
  return (
    <section
      className="overflow-hidden rounded-sm border border-border"
      aria-label={`Changes in ${file.path}`}
      data-testid="patch-file"
      data-path={file.path}
    >
      <header className="flex flex-wrap items-center gap-2 border-b border-border bg-surface-2 px-2 py-1.5">
        <StatusBadge state={change.state} label={change.label} />
        <span className="min-w-0 flex-1 break-all font-mono text-xs text-foreground">
          {file.oldPath && file.oldPath !== file.path ? `${file.oldPath} → ${file.path}` : file.path}
        </span>
        <span className="tnum text-xs text-foreground-secondary">
          {changeCountLabel(file.binary ? null : file.additions, file.binary ? null : file.deletions, file.binary)}
        </span>
        {hasRows ? (
          <button
            type="button"
            onClick={() => setOpen((value) => !value)}
            aria-expanded={open}
            className="inline-flex min-h-8 items-center gap-1 rounded-sm px-1.5 text-xs font-medium text-accent hover:bg-hover"
            data-testid="patch-file-toggle"
          >
            <Chevron className="size-3.5" aria-hidden="true" />
            {open ? 'Hide diff' : `Show ${rows} lines`}
          </button>
        ) : null}
      </header>
      {file.binary ? (
        <p className="px-2 py-2 text-xs text-foreground-tertiary">Binary file; its contents are not shown as text.</p>
      ) : !hasRows ? (
        <p className="px-2 py-2 text-xs text-foreground-tertiary">No line changes (mode or name only).</p>
      ) : open ? (
        <PatchRows file={file} />
      ) : (
        <p className="px-2 py-2 text-xs text-foreground-tertiary" data-testid="patch-file-collapsed">
          Long diff collapsed ({rows} lines).
        </p>
      )}
    </section>
  )
}

export function PatchView({ patch, files: parsedFiles }: { patch: string; files?: PatchFile[] }) {
  const files = useMemo(() => parsedFiles ?? parseUnifiedDiff(patch), [parsedFiles, patch])
  if (!patch.trim()) {
    return (
      <p className="text-xs text-foreground-tertiary" data-testid="patch-empty">
        The proposal carries no patch text to review.
      </p>
    )
  }
  if (files.length === 0) {
    // Not a diff StatePort can parse: show the exact text rather than hide it.
    return (
      <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-sm border border-border bg-sunken p-2 font-mono text-xs text-foreground-secondary" data-testid="patch-raw">
        {patch}
      </pre>
    )
  }
  return (
    <div className="flex flex-col gap-2" data-testid="patch-view">
      {files.map((file, index) => (
        <PatchFileSection key={`${file.path}#${index}`} file={file} />
      ))}
    </div>
  )
}
