/**
 * Conversation model helpers (design: conversation.md).
 *
 * Pure functions shared by the page, sidecar, composer and tests:
 * - context-chip construction (defaults + bridge payloads → chips)
 * - plain-language context explanation (the inspector's human sentence)
 * - attachment validation (allowed types / limits)
 * - transcript item list (day dividers + unread marker)
 * - assistant-content proposal extraction (command / patch code fences)
 */
import {
  FileText,
  LayoutGrid,
  ListChecks,
  Receipt,
  ShieldQuestion,
  SquareTerminal,
  TextSelect,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import type { ContextChip, ContextChipKind, ConversationMessage } from '@/client'
import type { BridgePayload } from '@/features/bridge/bridgeStore'

// ── Context chips ────────────────────────────────────────────────────────────

export const CHIP_ICON: Record<ContextChipKind, LucideIcon> = {
  application: LayoutGrid,
  file: FileText,
  selection: TextSelect,
  terminal: SquareTerminal,
  plan: ListChecks,
  approval: ShieldQuestion,
  receipt: Receipt,
  summary: LayoutGrid,
}

export const CHIP_KIND_WORD: Record<ContextChipKind, string> = {
  application: 'application',
  file: 'file',
  selection: 'selected code',
  terminal: 'terminal output',
  plan: 'plan',
  approval: 'approval',
  receipt: 'receipt',
  summary: 'application summary',
}

let localChipSeq = 0
function nextChipId(): string {
  localChipSeq += 1
  return `chip_local_${Date.now().toString(36)}_${localChipSeq}`
}

/** The two default chips (application identity + summary) per settings defaults. */
export function buildDefaultChips(instanceName: string, defaultKinds: ContextChipKind[]): ContextChip[] {
  const chips: ContextChip[] = [
    {
      id: 'chip_default_application',
      kind: 'application',
      label: instanceName,
      detail: 'The name, type and state of this application.',
      removable: false,
    },
  ]
  if (defaultKinds.includes('summary')) {
    chips.push({
      id: 'chip_default_summary',
      kind: 'summary',
      label: 'Application summary',
      detail: 'A short summary of this application’s current state.',
      removable: true,
    })
  }
  return chips
}

/** Map an inbound bridge payload to a context chip (never silent: always visible). */
export function bridgePayloadToChip(payload: BridgePayload): ContextChip | null {
  switch (payload.kind) {
    case 'file-selection': {
      const lines =
        payload.lineStart !== undefined
          ? `:${payload.lineStart}${payload.lineEnd !== undefined && payload.lineEnd !== payload.lineStart ? `–${payload.lineEnd}` : ''}`
          : ''
      return {
        id: nextChipId(),
        kind: 'selection',
        label: `${payload.path}${lines}`,
        detail: payload.text,
        removable: true,
      }
    }
    case 'file':
      return { id: nextChipId(), kind: 'file', label: payload.path, removable: true }
    case 'terminal-selection':
      return {
        id: nextChipId(),
        kind: 'terminal',
        label: 'Terminal selection',
        detail: payload.text,
        removable: true,
      }
    case 'receipt':
      return { id: nextChipId(), kind: 'receipt', label: `Receipt ${payload.receiptId}`, refId: payload.receiptId, removable: true }
    case 'plan':
      return { id: nextChipId(), kind: 'plan', label: `Plan ${payload.planId}`, refId: payload.planId, removable: true }
    case 'approval':
      return { id: nextChipId(), kind: 'approval', label: `Approval ${payload.approvalId}`, refId: payload.approvalId, removable: true }
    default:
      return null // outbound kinds (command-draft, patch-draft) never become chips
  }
}

/** One concise human sentence for the context inspector. */
export function contextSentence(chips: ContextChip[], instanceName: string): string {
  const parts: string[] = []
  const named = (c: ContextChip) => `the ${CHIP_KIND_WORD[c.kind]} \`${c.label}\``
  const hasApp = chips.some((c) => c.kind === 'application')
  if (hasApp) parts.push(`this application (${instanceName})`)
  for (const chip of chips) {
    if (chip.kind === 'application') continue
    if (chip.kind === 'summary') {
      parts.push('its current summary')
    } else {
      parts.push(named(chip))
    }
  }
  parts.push('your message')
  const list = parts.length <= 2 ? parts.join(' and ') : `${parts.slice(0, -1).join(', ')}, and ${parts[parts.length - 1]}`
  return `The assistant will see: ${list}. Nothing else is included.`
}

// ── Attachments ──────────────────────────────────────────────────────────────

// The authoritative attachment policy (2 MiB, backend media-type allowlist)
// lives in @/client/attachmentPolicy and is shared by the UI gate, the mock
// adapter, and the http adapter.
export {
  ALLOWED_ATTACHMENT_TYPES,
  ATTACHMENT_CONTEXT_NOTE,
  ATTACHMENT_LIMIT_HINT,
  checkAttachment,
  MAX_ATTACHMENT_BYTES,
} from '@/client/attachmentPolicy'
export type { AttachmentCheck } from '@/client/attachmentPolicy'

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// ── Transcript items (day dividers + unread marker) ─────────────────────────

export type TranscriptItem =
  | { type: 'day'; key: string; label: string }
  | { type: 'unread'; key: string; label: string }
  | { type: 'message'; key: string; message: ConversationMessage }

function dayKey(iso: string): string {
  const d = new Date(iso)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

export function dayLabel(iso: string): string {
  const today = dayKey(new Date().toISOString())
  const yesterdayDate = new Date()
  yesterdayDate.setDate(yesterdayDate.getDate() - 1)
  const yesterday = dayKey(yesterdayDate.toISOString())
  const key = dayKey(iso)
  if (key === today) return 'Today'
  if (key === yesterday) return 'Yesterday'
  return new Date(iso).toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' })
}

function timeLabel(iso: string): string {
  return new Date(iso).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

/**
 * Flatten messages into render items: day divider rows, an optional "New
 * since …" unread divider before the first message after `lastSeenId`, then
 * message rows. Pure — unit-testable without the DOM.
 */
export function buildTranscriptItems(
  messages: ConversationMessage[],
  opts: { lastSeenId?: string | null; unreadActive?: boolean } = {},
): TranscriptItem[] {
  const items: TranscriptItem[] = []
  let lastDay = ''
  // The unread divider sits immediately before the first message after the
  // last-seen one (only when there genuinely are newer messages).
  const seenIdx = opts.unreadActive && opts.lastSeenId ? messages.findIndex((m) => m.id === opts.lastSeenId) : -1
  const unreadBefore = seenIdx !== -1 && seenIdx < messages.length - 1 ? messages[seenIdx + 1].id : null
  const unreadLabel = seenIdx !== -1 ? `New since ${timeLabel(messages[seenIdx].createdAt)}` : ''
  for (const message of messages) {
    const day = dayKey(message.createdAt)
    if (day !== lastDay) {
      items.push({ type: 'day', key: `day_${day}`, label: dayLabel(message.createdAt) })
      lastDay = day
    }
    if (unreadBefore === message.id) {
      items.push({ type: 'unread', key: 'unread_marker', label: unreadLabel })
    }
    items.push({ type: 'message', key: message.id, message })
  }
  return items
}

// ── Assistant proposal extraction (command / patch code fences) ─────────────

export interface CommandProposal {
  kind: 'command'
  command: string
}

export interface PatchProposal {
  kind: 'patch'
  path: string
  proposed: string
}

export type ContentProposal = CommandProposal | PatchProposal

const FENCE_RE = /```(\w+)?\n([\s\S]*?)```/g

/**
 * Extract actionable proposals from assistant markdown: shell code fences
 * become "Insert into Terminal" proposals, diff fences become "Open as file
 * diff" proposals. Rendering stays markdown; these are additional actions —
 * never automatic (conversation.md: "never silent action").
 */
export function extractContentProposals(content: string): ContentProposal[] {
  const proposals: ContentProposal[] = []
  for (const match of content.matchAll(FENCE_RE)) {
    const lang = (match[1] ?? '').toLowerCase()
    const body = (match[2] ?? '').trim()
    if (!body) continue
    if (['sh', 'bash', 'shell', 'zsh', 'console', 'terminal'].includes(lang)) {
      proposals.push({ kind: 'command', command: body })
    } else if (lang === 'diff' || lang === 'patch') {
      const fileLine = body.split('\n').find((l) => l.startsWith('+++ b/') || l.startsWith('+++ '))
      const path = fileLine ? fileLine.replace(/^\+\+\+\s+(b\/)?/, '').trim() : 'proposed-change.diff'
      proposals.push({ kind: 'patch', path, proposed: body })
    }
  }
  return proposals
}

/** Redact fenced blocks from markdown when their proposal cards already show them. */
export function hasProposalFences(content: string): boolean {
  return extractContentProposals(content).length > 0
}
