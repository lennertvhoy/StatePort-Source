/**
 * Governed Files Markdown preview.
 *
 * This is deliberately a noncanonical projection of the current in-memory
 * draft. It reuses Conversation's hardened Markdown renderer, so raw HTML is
 * never rendered and non-HTTP(S) link schemes remain inert.
 */
import { Eye, FileText, Pencil } from 'lucide-react'

import { Markdown } from '@/features/conversation/Markdown'
import { cn } from '@/lib/utils'

export type MarkdownEditorMode = 'edit' | 'preview'

export function MarkdownModeToggle({
  path,
  mode,
  onChange,
}: {
  path: string
  mode: MarkdownEditorMode
  onChange: (mode: MarkdownEditorMode) => void
}) {
  return (
    <div
      className="flex h-9 shrink-0 items-center gap-1 border-b border-border bg-surface px-2"
      role="group"
      aria-label={`Markdown view for ${path}`}
      data-testid={`markdown-mode-${path}`}
    >
      {mode === 'preview' ? (
        <span className="min-w-0 flex-1 truncate text-xs text-foreground-secondary">
          <strong className="font-medium text-foreground">Draft preview</strong>{' '}
          · noncanonical
        </span>
      ) : (
        <span className="flex-1" aria-hidden="true" />
      )}
      <span className="flex shrink-0 items-center gap-1">
        <button
          type="button"
          aria-pressed={mode === 'edit'}
          onClick={() => onChange('edit')}
          className={cn(
            'inline-flex min-h-7 items-center gap-1.5 rounded-sm px-2 text-xs font-medium transition-colors duration-instant',
            mode === 'edit'
              ? 'bg-active text-foreground'
              : 'text-foreground-secondary hover:bg-hover hover:text-foreground',
          )}
          data-testid={`markdown-edit-${path}`}
        >
          <Pencil className="size-3.5" aria-hidden="true" />
          Edit
        </button>
        <button
          type="button"
          aria-pressed={mode === 'preview'}
          onClick={() => onChange('preview')}
          className={cn(
            'inline-flex min-h-7 items-center gap-1.5 rounded-sm px-2 text-xs font-medium transition-colors duration-instant',
            mode === 'preview'
              ? 'bg-active text-foreground'
              : 'text-foreground-secondary hover:bg-hover hover:text-foreground',
          )}
          data-testid={`markdown-preview-toggle-${path}`}
        >
          <Eye className="size-3.5" aria-hidden="true" />
          Preview
        </button>
      </span>
    </div>
  )
}

export function MarkdownPreview({
  path,
  content,
}: {
  path: string
  content: string
}) {
  return (
    <section
      className="flex h-full min-h-0 flex-col overflow-hidden bg-sunken"
      aria-label={`Noncanonical Markdown draft preview for ${path}`}
      data-testid={`markdown-preview-${path}`}
    >
      <p className="sr-only">
        Noncanonical draft preview. Rendered from the current in-memory draft.
        Previewing does not save or change application state.
      </p>
      <div className="min-h-0 flex-1 overflow-auto px-4 py-3">
        {content.trim() ? (
          <Markdown
            content={content}
            className="mx-auto max-w-3xl"
            variant="document"
          />
        ) : (
          <div
            className="flex h-full min-h-24 flex-col items-center justify-center gap-1.5 text-center"
            role="status"
            data-testid={`markdown-preview-empty-${path}`}
          >
            <FileText className="size-5 text-foreground-tertiary" aria-hidden="true" />
            <p className="text-sm font-medium text-foreground">Empty draft</p>
            <p className="max-w-sm text-xs text-foreground-secondary">
              The current in-memory draft has no Markdown to preview. Nothing
              was saved or changed.
            </p>
          </div>
        )}
      </div>
    </section>
  )
}
