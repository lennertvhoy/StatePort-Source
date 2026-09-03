/**
 * StatusStrip (files.md §Layout) — the editor-local 24 px strip at the bottom
 * of the canvas: cursor Ln/Col · indentation · language · encoding · dirty /
 * read-only state · "Send selection to Conversation" when a selection exists
 * · "Review & save" when dirty · related receipt link after a validated save.
 * All mono 12 px tabular.
 */
import { CircleDot, Lock, MessageSquare, Receipt, Save } from 'lucide-react'

import { Tooltip } from '@/components'
import { languageNameFor } from './language'
import type { EditorCursor, EditorSelectionInfo } from './CodeEditor'

export interface StatusStripProps {
  path: string
  cursor: EditorCursor | null
  selection: EditorSelectionInfo | null
  dirty: boolean
  readOnly: boolean
  indentWith: 'spaces' | 'tabs'
  tabSize: number
  lastReceiptId: string | null
  onReviewSave: () => void
  onSendSelection: () => void
  onOpenReceipt: (receiptId: string) => void
}

function Item({ children, label }: { children: React.ReactNode; label?: string }) {
  return (
    <span
      className="tnum flex h-full items-center gap-1 border-r border-border px-2 font-mono text-xs text-foreground-secondary"
      aria-label={label}
    >
      {children}
    </span>
  )
}

export function StatusStrip({
  path,
  cursor,
  selection,
  dirty,
  readOnly,
  indentWith,
  tabSize,
  lastReceiptId,
  onReviewSave,
  onSendSelection,
  onOpenReceipt,
}: StatusStripProps) {
  return (
    <div
      className="flex h-6 shrink-0 items-stretch border-t border-border bg-surface"
      data-testid="editor-status-strip"
      aria-label="Editor status"
    >
      <Item label="Cursor position">{cursor ? `Ln ${cursor.line}, Col ${cursor.column}` : 'Ln —, Col —'}</Item>
      <Item label="Indentation">{indentWith === 'tabs' ? 'Tabs' : `Spaces: ${tabSize}`}</Item>
      <Item label="Language">{languageNameFor(path)}</Item>
      <Item label="Encoding">UTF-8</Item>
      {readOnly ? (
        <Item label="Read-only">
          <Lock className="size-3" aria-hidden="true" />
          Read-only
        </Item>
      ) : null}
      {dirty ? (
        <Item label="Unsaved changes">
          <CircleDot className="size-3 text-accent" aria-hidden="true" />
          <span className="text-accent">Unsaved changes</span>
        </Item>
      ) : null}
      <span className="flex-1" />
      {lastReceiptId ? (
        <Tooltip content="Open the receipt created by the last validated save">
          <button
            type="button"
            onClick={() => onOpenReceipt(lastReceiptId)}
            className="tnum flex h-full items-center gap-1 border-l border-border px-2 font-mono text-xs text-accent transition-colors duration-instant hover:bg-hover"
            data-testid="status-receipt-link"
          >
            <Receipt className="size-3" aria-hidden="true" />
            Receipt
          </button>
        </Tooltip>
      ) : null}
      {selection ? (
        <button
          type="button"
          onClick={onSendSelection}
          className="tnum flex h-full items-center gap-1 border-l border-border px-2 font-mono text-xs text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          data-testid="status-send-selection"
        >
          <MessageSquare className="size-3" aria-hidden="true" />
          Send selection to Conversation
        </button>
      ) : null}
      {dirty ? (
        <button
          type="button"
          onClick={onReviewSave}
          className="tnum flex h-full items-center gap-1 border-l border-border bg-accent-soft px-2 font-mono text-xs font-medium text-accent-soft-text transition-colors duration-instant hover:bg-hover"
          data-testid="status-review-save"
        >
          <Save className="size-3" aria-hidden="true" />
          Review &amp; save
        </button>
      ) : null}
    </div>
  )
}
