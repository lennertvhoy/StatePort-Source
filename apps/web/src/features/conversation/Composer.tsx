/**
 * Composer — the centerpiece of the conversation surface (conversation.md
 * "Composer behavior" is binding).
 *
 * - Desktop: Enter sends / Shift+Enter newline / Ctrl+Cmd+Enter always sends.
 *   Mobile (coarse pointer): Enter = newline, dedicated Send button.
 *   The `enterSends` setting flips the desktop default.
 * - IME-safe: compositionstart/end + isComposing — Enter during composition
 *   never sends.
 * - Auto-grows to a max height, then scrolls internally.
 * - Per-conversation drafts persist (workspace store); attachments never
 *   touch draft text.
 * - Send is disabled ONLY when there is no content and no valid attachment.
 * - Context chips row + inspector: exactly what will be sent, removable.
 * - Slash commands (curated safe set): /clear /export /context /help.
 */
import {
  ArrowUp,
  CircleHelp,
  Download,
  FileText,
  Info,
  LayoutGrid,
  Paperclip,
  RotateCcw,
  SlashSquare,
  Trash2,
  X,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { forwardRef, useCallback, useEffect, useImperativeHandle, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'

import type { ContextChip, ConversationSettings } from '@/client'
import { Tooltip } from '@/components'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { cn } from '@/lib/utils'
import { useMediaQuery } from '@/shell/platform'
import { useWorkspaceStore } from '@/state'

import type { SendInput } from './useConversationController'
import type { ContextChipsState } from './useContextChips'
import { useAttachmentUploads } from './useAttachmentUploads'
import {
  ALLOWED_ATTACHMENT_TYPES,
  ATTACHMENT_CONTEXT_NOTE,
  ATTACHMENT_LIMIT_HINT,
  CHIP_ICON,
  CHIP_KIND_WORD,
  contextSentence,
  formatBytes,
} from './conversationModel'

const MAX_TEXTAREA_HEIGHT = 240 // ~10 lines at 13/20 + padding, then internal scroll

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(reader.error ?? new Error('File could not be read'))
    reader.onload = () => {
      const result = reader.result
      if (typeof result !== 'string' || !result.includes(',')) {
        reject(new Error('File could not be encoded'))
        return
      }
      resolve(result.slice(result.indexOf(',') + 1))
    }
    reader.readAsDataURL(file)
  })
}

// ── Slash commands (curated safe set) ────────────────────────────────────────

interface SlashCommand {
  id: 'clear' | 'export' | 'context' | 'help'
  name: string
  description: string
  icon: LucideIcon
}

const SLASH_COMMANDS: readonly SlashCommand[] = [
  { id: 'clear', name: '/clear', description: 'Clear history after confirmation', icon: Trash2 },
  { id: 'export', name: '/export', description: 'Download as Markdown and record a receipt', icon: Download },
  { id: 'context', name: '/context', description: 'Show exactly what will be sent', icon: LayoutGrid },
  { id: 'help', name: '/help', description: 'Composer keyboard behavior', icon: CircleHelp },
]

// ── Context chips + inspector ────────────────────────────────────────────────

function ContextChipPill({ chip, onRemove }: { chip: ContextChip; onRemove: (id: string) => void }) {
  const Icon = CHIP_ICON[chip.kind]
  return (
    <span
      className="inline-flex max-w-52 items-center gap-1 rounded-sm border border-border bg-surface-2 px-1.5 py-0.5 text-xs text-foreground-secondary"
      data-testid={`context-chip-${chip.kind}`}
      title={chip.detail ?? chip.label}
    >
      <Icon className="size-3 shrink-0" aria-hidden="true" />
      <span className="truncate">{chip.label}</span>
      {chip.removable ? (
        <button
          type="button"
          aria-label={`Remove ${chip.label} from context`}
          data-testid={`remove-chip-${chip.id}`}
          className="inline-flex size-4 shrink-0 items-center justify-center rounded-xs text-foreground-tertiary hover:bg-hover hover:text-foreground"
          onClick={() => onRemove(chip.id)}
        >
          <X className="size-3" aria-hidden="true" />
        </button>
      ) : null}
    </span>
  )
}

function ContextInspector({
  chips,
  instanceName,
  onRemove,
}: {
  chips: ContextChip[]
  instanceName: string
  onRemove: (id: string) => void
}) {
  return (
    <div className="flex flex-col gap-2.5" data-testid="context-inspector">
      <p className="text-sm text-foreground">{contextSentence(chips, instanceName)}</p>
      <ul className="flex flex-col gap-1.5">
        {chips.map((chip) => {
          const Icon = CHIP_ICON[chip.kind]
          return (
            <li key={chip.id} className="flex items-start gap-2 text-xs">
              <Icon className="mt-0.5 size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-medium text-foreground">
                  {CHIP_KIND_WORD[chip.kind]} — {chip.label}
                </span>
                <span className="block text-foreground-tertiary">{chip.detail ?? 'Included exactly as selected.'}</span>
              </span>
              {chip.removable ? (
                <button
                  type="button"
                  aria-label={`Remove ${chip.label} from context`}
                  className="inline-flex size-5 shrink-0 items-center justify-center rounded-xs text-foreground-tertiary hover:bg-hover hover:text-foreground"
                  onClick={() => onRemove(chip.id)}
                >
                  <X className="size-3" aria-hidden="true" />
                </button>
              ) : (
                <span className="shrink-0 text-foreground-tertiary">always</span>
              )}
            </li>
          )
        })}
      </ul>
      <p className="border-t border-border pt-2 text-xs text-foreground-tertiary">
        Never included: unselected files, full terminal transcripts, credentials, raw provider prompts, and other
        applications.{' '}
        <Link to="/settings/privacy" className="text-accent underline underline-offset-2">
          Privacy settings
        </Link>
      </p>
    </div>
  )
}

// ── Attachment strip ─────────────────────────────────────────────────────────

function AttachmentStrip({
  uploads,
}: {
  uploads: ReturnType<typeof useAttachmentUploads>
}) {
  if (uploads.pending.length === 0) return null
  return (
    <ul className="flex flex-wrap gap-1.5 px-3 pt-2" aria-label="Attachments" data-testid="attachment-strip">
      {uploads.pending.map((a) => (
        <li
          key={a.id}
          className={cn(
            'relative inline-flex max-w-64 flex-wrap items-center gap-1.5 overflow-hidden rounded-sm border px-2 py-1 text-xs',
            a.state === 'failed' ? 'border-status-danger-border text-status-danger' : 'border-border text-foreground-secondary',
          )}
          data-testid={`attachment-${a.state}`}
        >
          {a.state === 'uploading' ? (
            <span
              className="absolute inset-x-0 bottom-0 h-0.5 bg-accent transition-[width] duration-fast"
              style={{ width: `${a.progress ?? 0}%` }}
              role="progressbar"
              aria-valuenow={a.progress ?? 0}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={`Uploading ${a.name}`}
            />
          ) : null}
          <FileText className="size-3 shrink-0" aria-hidden="true" />
          <span className="truncate">{a.name}</span>
          <span className="tnum shrink-0 font-mono text-foreground-tertiary">{formatBytes(a.sizeBytes)}</span>
          {a.state === 'uploading' ? <span className="shrink-0 text-foreground-tertiary">{a.progress ?? 0}%</span> : null}
          {a.state === 'failed' ? (
            <>
              <span className="shrink-0 font-medium">failed</span>
              {uploads.canRetry(a.id) ? (
                <button
                  type="button"
                  aria-label={`Retry uploading ${a.name}`}
                  data-testid={`retry-attachment-${a.id}`}
                  className="inline-flex size-4 shrink-0 items-center justify-center rounded-xs hover:bg-hover"
                  onClick={() => uploads.retry(a.id)}
                >
                  <RotateCcw className="size-3" aria-hidden="true" />
                </button>
              ) : null}
            </>
          ) : null}
          <button
            type="button"
            aria-label={`Remove ${a.name}`}
            data-testid={`remove-attachment-${a.id}`}
            className="inline-flex size-4 shrink-0 items-center justify-center rounded-xs hover:bg-hover hover:text-foreground"
            onClick={() => uploads.remove(a.id)}
          >
            <X className="size-3" aria-hidden="true" />
          </button>
          {a.state === 'failed' ? (
            <p
              role="alert"
              className="w-full border-t border-status-danger-border pt-1 text-left leading-4"
              data-testid={`attachment-error-${a.id}`}
            >
              {a.error ?? 'Upload failed before completion.'}
            </p>
          ) : null}
        </li>
      ))}
    </ul>
  )
}

// ── The composer ─────────────────────────────────────────────────────────────

export interface ComposerHandle {
  focus(): void
  /** Insert text at the end of the draft and focus (quote / edit flows). */
  insertText(text: string): void
}

export interface ComposerProps {
  instanceId: string
  /** Draft persistence key (one conversation per application). */
  draftKey: string
  settings: ConversationSettings
  streaming: boolean
  onSend: (input: SendInput) => void
  chipsState: ContextChipsState
  instanceName: string
  dense?: boolean
  /** Slash-command side effects owned by the page (clear dialog, export). */
  onSlashAction: (action: 'clear' | 'export') => void
  /** ↑ in an empty composer: edit the last failed/unsent message. */
  onEditLastFailed?: () => void
}

export const Composer = forwardRef<ComposerHandle, ComposerProps>(function Composer(
  { instanceId, draftKey, settings, streaming, onSend, chipsState, instanceName, dense, onSlashAction, onEditLastFailed },
  ref,
) {
  const setDraft = useWorkspaceStore((s) => s.setDraft)
  const clearDraft = useWorkspaceStore((s) => s.clearDraft)

  const [text, setText] = useState(() =>
    settings.draftPersistence ? (useWorkspaceStore.getState().drafts[draftKey] ?? '') : '',
  )
  const [inspectorOpen, setInspectorOpen] = useState(false)
  const [limitsOpen, setLimitsOpen] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  const [dragActive, setDragActive] = useState(false)
  const [slashIndex, setSlashIndex] = useState(0)

  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const composingRef = useRef(false)
  const draftTimerRef = useRef<number | null>(null)
  // Keep the latest value per conversation key. Effect cleanup for the old
  // key runs after a render for the new key, so one shared "latest" ref would
  // otherwise save the new conversation's text into the old conversation.
  const draftStateRef = useRef(
    new Map<string, { text: string; persist: boolean }>([
      [draftKey, { text, persist: settings.draftPersistence }],
    ]),
  )

  const uploads = useAttachmentUploads(instanceId)
  const coarsePointer = useMediaQuery('(pointer: coarse)')

  // ── Draft restore per conversation (render-adjust on key change) ──────────
  const [prevDraftKey, setPrevDraftKey] = useState(draftKey)
  if (prevDraftKey !== draftKey) {
    const restored = settings.draftPersistence ? (useWorkspaceStore.getState().drafts[draftKey] ?? '') : ''
    setPrevDraftKey(draftKey)
    setText(restored)
    draftStateRef.current.set(draftKey, { text: restored, persist: settings.draftPersistence })
  } else {
    draftStateRef.current.set(draftKey, { text, persist: settings.draftPersistence })
  }

  // Debounced draft save — attachments never touch this path.
  useEffect(() => {
    if (!settings.draftPersistence) return
    if (draftTimerRef.current !== null) window.clearTimeout(draftTimerRef.current)
    draftTimerRef.current = window.setTimeout(() => setDraft(draftKey, text), 250)
    return () => {
      if (draftTimerRef.current !== null) window.clearTimeout(draftTimerRef.current)
    }
  }, [text, draftKey, settings.draftPersistence, setDraft])

  // A route change can unmount the composer before the debounce above fires.
  // Flush the latest text at that boundary so local draft continuity never
  // depends on how quickly the user navigates away.
  useEffect(
    () => () => {
      const latest = draftStateRef.current.get(draftKey)
      if (!latest?.persist) return
      if (draftTimerRef.current !== null) window.clearTimeout(draftTimerRef.current)
      if (latest.text) setDraft(draftKey, latest.text)
      else clearDraft(draftKey)
    },
    [clearDraft, draftKey, setDraft],
  )

  // ── Auto-grow ──────────────────────────────────────────────────────────────
  const resize = useCallback(() => {
    const el = textareaRef.current
    if (!el) return
    el.style.height = '0px'
    const next = Math.min(el.scrollHeight, MAX_TEXTAREA_HEIGHT)
    el.style.height = `${next}px`
    el.style.overflowY = el.scrollHeight > MAX_TEXTAREA_HEIGHT ? 'auto' : 'hidden'
  }, [])
  useEffect(resize, [text, resize, dense])

  const focus = useCallback(() => {
    const el = textareaRef.current
    if (!el) return
    el.focus()
    const len = el.value.length
    el.setSelectionRange(len, len)
  }, [])

  const insertText = useCallback(
    (insert: string) => {
      setText((prev) => (prev.trim() ? `${prev.replace(/\n+$/, '')}\n${insert}` : insert))
      // Focus after the state flush so the caret lands at the end.
      window.setTimeout(focus, 0)
    },
    [focus],
  )

  useImperativeHandle(ref, () => ({ focus, insertText }), [focus, insertText])

  // ── Slash menu ─────────────────────────────────────────────────────────────
  const slashMatch = /^\/(\w*)$/.exec(text)
  const slashOpen = slashMatch !== null
  const slashQuery = slashMatch?.[1] ?? ''
  const slashFiltered = useMemo(
    () => SLASH_COMMANDS.filter((c) => c.name.slice(1).startsWith(slashQuery.toLowerCase())),
    [slashQuery],
  )
  const [prevSlashQuery, setPrevSlashQuery] = useState(slashQuery)
  if (prevSlashQuery !== slashQuery) {
    setPrevSlashQuery(slashQuery)
    setSlashIndex(0)
  }

  const runSlashCommand = useCallback(
    (command: SlashCommand) => {
      setText('')
      if (command.id === 'context') setInspectorOpen(true)
      else if (command.id === 'help') setHelpOpen((v) => !v)
      else onSlashAction(command.id)
      focus()
    },
    [focus, onSlashAction],
  )

  // ── Send ───────────────────────────────────────────────────────────────────
  const canSend = text.trim().length > 0 || uploads.hasReady

  const doSend = useCallback(() => {
    if (!canSend) return
    const ready = uploads.takeReady()
    onSend({ content: text.trim(), attachments: ready, contextChips: chipsState.chips })
    draftStateRef.current.set(draftKey, { text: '', persist: settings.draftPersistence })
    setText('')
    clearDraft(draftKey)
    chipsState.resetChips()
    window.setTimeout(focus, 0)
  }, [canSend, uploads, text, onSend, chipsState, clearDraft, draftKey, focus, settings.draftPersistence])

  // ── Keyboard (IME-safe) ────────────────────────────────────────────────────
  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'ArrowUp' && text === '' && onEditLastFailed) {
      e.preventDefault()
      onEditLastFailed()
      return
    }
    if (slashOpen && slashFiltered.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSlashIndex((i) => (i + 1) % slashFiltered.length)
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSlashIndex((i) => (i - 1 + slashFiltered.length) % slashFiltered.length)
        return
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault()
        runSlashCommand(slashFiltered[Math.min(slashIndex, slashFiltered.length - 1)])
        return
      }
      if (e.key === 'Escape') {
        setText('')
        return
      }
    }
    if (e.key !== 'Enter') return
    // IME: never send while text composition is active.
    if (composingRef.current || e.nativeEvent.isComposing) return
    if ((e.ctrlKey || e.metaKey) && e.shiftKey) return // Ctrl/Cmd+Shift+Enter = focus mode (surface scope)
    if (e.ctrlKey || e.metaKey) {
      // Ctrl/Cmd+Enter always sends (both platforms, both settings).
      e.preventDefault()
      doSend()
      return
    }
    if (e.shiftKey) return // newline
    if (coarsePointer) return // mobile: Enter = newline; the Send button sends
    if (settings.enterSends) {
      e.preventDefault()
      doSend()
    }
    // enterSends off: Enter = newline, Ctrl/Cmd+Enter sends (handled above).
  }

  // ── Files: button / drag-drop / paste ──────────────────────────────────────
  const addFileList = useCallback(
    (files: Iterable<File>) => {
      const selected = [...files]
      void Promise.all(
        selected.map(async (file) => ({
          name: file.name,
          mimeType: file.type,
          sizeBytes: file.size,
          contentBase64: await fileToBase64(file),
        })),
      ).then((list) => {
        if (list.length > 0) uploads.addFiles(list)
      }).catch(() => {
        // Preserve a visible, retryable failed chip. The production adapter
        // refuses metadata-only uploads, so this can never fabricate success.
        uploads.addFiles(selected.map((file) => ({
          name: file.name,
          mimeType: file.type,
          sizeBytes: file.size,
        })))
      })
    },
    [uploads],
  )

  const onPaste = (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    if (e.clipboardData.files.length > 0) {
      e.preventDefault()
      addFileList(e.clipboardData.files)
    }
  }

  const hasInvalidUpload = uploads.pending.some((a) => a.state === 'failed')
  const showLimits = limitsOpen || dragActive || hasInvalidUpload

  const hint = coarsePointer
    ? 'Enter adds a new line'
    : settings.enterSends
      ? 'Enter to send · Shift+Enter for a new line'
      : 'Ctrl+Enter to send · Enter adds a new line'

  return (
    <div
      className={cn('relative', dragActive && 'z-10')}
      onDragOver={(e) => {
        if (e.dataTransfer.types.includes('Files')) {
          e.preventDefault()
          setDragActive(true)
        }
      }}
      onDragLeave={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) setDragActive(false)
      }}
      onDrop={(e) => {
        if (e.dataTransfer.files.length > 0) {
          e.preventDefault()
          setDragActive(false)
          addFileList(e.dataTransfer.files)
        }
      }}
      data-testid="composer"
    >
      {dragActive ? (
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-md border-2 border-dashed border-accent bg-accent-soft/60 text-sm font-medium text-accent-soft-text">
          Drop files to attach — {ATTACHMENT_LIMIT_HINT}
        </div>
      ) : null}

      <div className="rounded-md border border-input bg-surface shadow-none transition-colors duration-instant focus-within:border-accent">
        {/* Context chips row — only when non-default context is attached. */}
        {chipsState.hasNonDefault ? (
          <div className="flex flex-wrap items-center gap-1 border-b border-border px-3 py-1.5" data-testid="context-chip-row">
            {chipsState.chips.map((chip) => (
              <ContextChipPill key={chip.id} chip={chip} onRemove={chipsState.removeChip} />
            ))}
            <Popover open={inspectorOpen} onOpenChange={setInspectorOpen}>
              <PopoverTrigger asChild>
                <button
                  type="button"
                  className="ml-auto text-xs text-accent hover:underline"
                  data-testid="whats-included"
                >
                  What’s included
                </button>
              </PopoverTrigger>
              <PopoverContent align="end" className="w-80 bg-surface">
                <ContextInspector chips={chipsState.chips} instanceName={instanceName} onRemove={chipsState.removeChip} />
              </PopoverContent>
            </Popover>
          </div>
        ) : null}

        <AttachmentStrip uploads={uploads} />

        {/* Slash command menu */}
        {slashOpen && slashFiltered.length > 0 ? (
          <div
            role="listbox"
            aria-label="Slash commands"
            className="mx-3 mt-2 overflow-hidden rounded-md border border-border bg-surface shadow-1"
            data-testid="slash-menu"
          >
            {slashFiltered.map((command, index) => (
              <button
                key={command.id}
                type="button"
                role="option"
                aria-selected={index === slashIndex}
                className={cn(
                  'flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-sm',
                  index === slashIndex ? 'bg-hover text-foreground' : 'text-foreground-secondary',
                )}
                onMouseEnter={() => setSlashIndex(index)}
                onClick={() => runSlashCommand(command)}
              >
                <command.icon className="size-4 shrink-0" aria-hidden="true" />
                <span className="font-mono text-xs">{command.name}</span>
                <span className="truncate text-xs">{command.description}</span>
              </button>
            ))}
          </div>
        ) : null}

        {helpOpen ? (
          <div className="mx-3 mt-2 rounded-md border border-border bg-surface-2 p-2.5 text-xs text-foreground-secondary" data-testid="composer-help">
            <p className="font-medium text-foreground">Composer keyboard</p>
            <ul className="mt-1 flex flex-col gap-0.5">
              <li>Enter sends on desktop; Shift+Enter adds a new line. Ctrl/Cmd+Enter always sends.</li>
              <li>On touch devices Enter adds a new line — the Send button sends.</li>
              <li>Escape stops a streaming response. ↑ in an empty composer edits the last failed message.</li>
              <li>Slash commands: /clear /export /context /help.</li>
            </ul>
          </div>
        ) : null}

        <div className="flex items-end gap-1.5 px-2 py-1.5">
          <div className="flex items-center gap-0.5 pb-0.5">
            <Tooltip content="Attach files">
              <button
                type="button"
                aria-label="Attach files"
                data-testid="attach-button"
                className="inline-flex size-8 min-h-[var(--min-target,2rem)] min-w-[var(--min-target,2rem)] items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                onClick={() => fileInputRef.current?.click()}
              >
                <Paperclip className="size-4" aria-hidden="true" />
              </button>
            </Tooltip>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept={ALLOWED_ATTACHMENT_TYPES.join(',')}
              className="hidden"
              data-testid="composer-file-input"
              aria-label="Choose files to attach"
              onChange={(e) => {
                if (e.target.files) addFileList(e.target.files)
                e.target.value = ''
              }}
            />
            <Tooltip content="Slash commands">
              <button
                type="button"
                aria-label="Slash commands"
                data-testid="slash-button"
                className="inline-flex size-8 min-h-[var(--min-target,2rem)] min-w-[var(--min-target,2rem)] items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                onClick={() => {
                  setText('/')
                  focus()
                }}
              >
                <SlashSquare className="size-4" aria-hidden="true" />
              </button>
            </Tooltip>
          </div>

          <textarea
            ref={textareaRef}
            value={text}
            rows={1}
            aria-label="Message"
            data-testid="composer-input"
            placeholder="Message…"
            className="min-h-8 flex-1 resize-none bg-transparent px-1.5 py-1.5 text-md text-foreground outline-none placeholder:text-foreground-tertiary"
            onChange={(e) => setText(e.target.value)}
            onKeyDown={onKeyDown}
            onPaste={onPaste}
            onCompositionStart={() => {
              composingRef.current = true
            }}
            onCompositionEnd={() => {
              composingRef.current = false
            }}
          />

          <div className="flex items-center gap-0.5 pb-0.5">
            {!chipsState.hasNonDefault ? (
              <Popover open={inspectorOpen} onOpenChange={setInspectorOpen}>
                <PopoverTrigger asChild>
                  <button
                    type="button"
                    aria-label="What will be sent as context"
                    data-testid="context-button"
                    className="inline-flex size-8 min-h-[var(--min-target,2rem)] min-w-[var(--min-target,2rem)] items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                  >
                    <LayoutGrid className="size-4" aria-hidden="true" />
                  </button>
                </PopoverTrigger>
                <PopoverContent align="end" className="w-80 bg-surface">
                  <ContextInspector chips={chipsState.chips} instanceName={instanceName} onRemove={chipsState.removeChip} />
                </PopoverContent>
              </Popover>
            ) : null}
            <Tooltip content={ATTACHMENT_LIMIT_HINT}>
              <button
                type="button"
                aria-label="Attachment types and limits"
                aria-expanded={limitsOpen}
                data-testid="limits-button"
                className={cn(
                  'inline-flex size-8 items-center justify-center rounded-sm transition-colors duration-instant hover:bg-hover',
                  limitsOpen ? 'text-foreground' : 'text-foreground-tertiary',
                )}
                onClick={() => setLimitsOpen((v) => !v)}
              >
                <Info className="size-4" aria-hidden="true" />
              </button>
            </Tooltip>
            <button
              type="button"
              aria-label={streaming ? 'Send message (a response is still streaming)' : 'Send message'}
              data-testid="composer-send"
              disabled={!canSend}
              onClick={doSend}
              className={cn(
                'inline-flex size-8 min-h-[var(--min-target,2rem)] min-w-[var(--min-target,2rem)] items-center justify-center rounded-sm transition-colors duration-instant',
                canSend ? 'bg-accent text-foreground-inverse hover:bg-accent-hover' : 'bg-active text-foreground-disabled',
              )}
            >
              <ArrowUp className="size-4" aria-hidden="true" />
            </button>
          </div>
        </div>
      </div>

      {showLimits ? (
        <div className="mt-1 px-1 text-xs text-foreground-tertiary" data-testid="limits-hint">
          <p>{ATTACHMENT_LIMIT_HINT}</p>
          <p>{ATTACHMENT_CONTEXT_NOTE}</p>
        </div>
      ) : null}

      <p className="mt-1 px-1 text-right text-xs text-foreground-tertiary" data-testid="composer-hint">
        {hint}
      </p>
    </div>
  )
})
