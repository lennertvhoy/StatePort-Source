/**
 * MessageRow — one transcript row (conversation.md: rows, not chat bubbles).
 *
 * User messages: subtle surface block. Assistant messages: on the background
 * with a 2 px strong left marker. Honest state markers ("Not sent", "Stopped
 * by you", "Response interrupted"), collapsible tool events, and proposal
 * cards that bridge to Terminal / Files / Approvals — never silent action.
 */
import {
  ChevronRight,
  FileDiff,
  FileText,
  ListChecks,
  Pencil,
  Pin,
  PinOff,
  Quote,
  RotateCcw,
  ShieldQuestion,
  SquareTerminal,
  Trash2,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { memo, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import type { Attachment, ContextChip, ConversationMessage } from '@/client'
import { CopyButton, OperationStateLabel, TimeAgo, Tooltip } from '@/components'
import { sendToBridge } from '@/features/bridge/bridgeStore'
import { cn } from '@/lib/utils'
import { useSessionStore } from '@/state'

import { CHIP_ICON, extractContentProposals, formatBytes } from './conversationModel'
import { Markdown } from './Markdown'

// ── Small icon action button (hover actions, proposal cards) ────────────────

export function IconAction({
  icon: Icon,
  label,
  onClick,
  className,
  testId,
}: {
  icon: LucideIcon
  label: string
  onClick: () => void
  className?: string
  testId?: string
}) {
  return (
    <Tooltip content={label}>
      <button
        type="button"
        aria-label={label}
        onClick={onClick}
        data-testid={testId}
        className={cn(
          'inline-flex size-7 min-h-[var(--min-target,1.75rem)] min-w-[var(--min-target,1.75rem)] items-center justify-center rounded-sm text-foreground-tertiary transition-colors duration-instant hover:bg-hover hover:text-foreground',
          className,
        )}
      >
        <Icon className="size-3.5" aria-hidden="true" />
      </button>
    </Tooltip>
  )
}

// ── Attachment + context chips on messages ───────────────────────────────────

function AttachmentChip({ attachment }: { attachment: Attachment }) {
  return (
    <Tooltip content={attachment.retentionNote ?? 'Stored locally with this conversation.'}>
      <span className="inline-flex max-w-56 items-center gap-1.5 rounded-sm border border-border bg-surface px-2 py-1 text-xs text-foreground-secondary">
        <FileText className="size-3 shrink-0" aria-hidden="true" />
        <span className="truncate">{attachment.name}</span>
        <span className="tnum shrink-0 font-mono text-foreground-tertiary">{formatBytes(attachment.sizeBytes)}</span>
      </span>
    </Tooltip>
  )
}

function SentContextChip({ chip }: { chip: ContextChip }) {
  const Icon = CHIP_ICON[chip.kind]
  return (
    <Tooltip content={chip.detail ?? chip.label}>
      <span className="inline-flex max-w-48 items-center gap-1 rounded-sm bg-surface-2 px-1.5 py-0.5 text-xs text-foreground-tertiary">
        <Icon className="size-3 shrink-0" aria-hidden="true" />
        <span className="truncate">{chip.label}</span>
      </span>
    </Tooltip>
  )
}

// ── Tool / run events (collapsed by default) ─────────────────────────────────

function ToolEvents({ message, defaultExpanded }: { message: ConversationMessage; defaultExpanded: boolean }) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  const events = message.toolEvents
  if (events.length === 0) return null
  const first = events[0]
  const summary = events.length === 1 ? first.summary : `${first.summary} (+${events.length - 1} more)`
  return (
    <div className="mt-2 rounded-sm border border-border bg-surface-2" data-testid="tool-events">
      <button
        type="button"
        className="flex w-full items-center gap-1.5 px-2 py-1.5 text-left text-xs text-foreground-secondary hover:text-foreground"
        aria-expanded={expanded}
        onClick={() => setExpanded((v) => !v)}
      >
        <ChevronRight className={cn('size-3.5 shrink-0 transition-transform duration-fast', expanded && 'rotate-90')} aria-hidden="true" />
        <ListChecks className="size-3.5 shrink-0" aria-hidden="true" />
        <span className="truncate">
          {summary} — {expanded ? 'collapse' : 'expand'}
        </span>
      </button>
      {expanded ? (
        <ul className="border-t border-border px-2 py-1.5">
          {events.map((event) => (
            <li key={event.id} className="flex flex-col gap-0.5 py-1">
              <span className="flex items-center gap-2">
                <OperationStateLabel state={event.state} className="text-xs" />
                <span className="font-mono text-xs text-foreground-tertiary">{event.kind}</span>
              </span>
              <span className="text-xs text-foreground-secondary">{event.summary}</span>
              {event.detail ? (
                <pre className="mt-0.5 overflow-x-auto rounded-xs bg-sunken p-1.5 font-mono text-xs text-foreground-secondary">
                  {event.detail}
                </pre>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}

// ── Proposal cards (bridges — never silent action) ───────────────────────────

function ProposalCard({
  icon: Icon,
  title,
  children,
  actions,
}: {
  icon: LucideIcon
  title: string
  children?: React.ReactNode
  actions: React.ReactNode
}) {
  return (
    <div className="mt-2 rounded-md border border-border bg-surface p-2.5" data-testid="proposal-card">
      <div className="flex items-center gap-1.5 text-sm font-medium text-foreground">
        <Icon className="size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
        <span className="truncate">{title}</span>
      </div>
      {children}
      <div className="mt-2 flex flex-wrap items-center gap-2">{actions}</div>
      <p className="mt-1.5 text-xs text-foreground-tertiary">Nothing has been run or changed.</p>
    </div>
  )
}

function CardButton({ icon: Icon, label, onClick, primary, testId }: { icon: LucideIcon; label: string; onClick: () => void; primary?: boolean; testId?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      data-testid={testId}
      className={cn(
        'inline-flex h-7 items-center gap-1.5 rounded-sm px-2 text-xs font-medium transition-colors duration-instant',
        primary ? 'bg-accent text-foreground-inverse hover:bg-accent-hover' : 'border border-border text-foreground hover:bg-hover',
      )}
    >
      <Icon className="size-3.5" aria-hidden="true" />
      {label}
    </button>
  )
}

function ProposalCards({ message, instanceId }: { message: ConversationMessage; instanceId: string }) {
  const navigate = useNavigate()
  const pushToast = useSessionStore((s) => s.pushToast)
  const cards: React.ReactNode[] = []

  if (message.proposal) {
    const proposal = message.proposal
    cards.push(
      <ProposalCard
        key="governed"
        icon={ShieldQuestion}
        title={proposal.title}
        actions={
          <CardButton
            icon={ShieldQuestion}
            label="Open the approvals flow"
            primary
            testId="proposal-open-approval"
            onClick={() => {
              if (proposal.actionRoute) navigate(proposal.actionRoute)
              else navigate('/approvals')
            }}
          />
        }
      >
        <p className="mt-1 text-xs text-foreground-secondary">{proposal.detail}</p>
      </ProposalCard>,
    )
  }

  for (const [index, proposal] of extractContentProposals(message.content).entries()) {
    if (proposal.kind === 'command') {
      cards.push(
        <ProposalCard
          key={`cmd_${index}`}
          icon={SquareTerminal}
          title="Proposed command"
          actions={
            <>
              <CardButton
                icon={SquareTerminal}
                label="Insert into Terminal"
                primary
                testId="proposal-insert-terminal"
                onClick={() => {
                  sendToBridge({ kind: 'command-draft', instanceId, command: proposal.command })
                  pushToast({
                    kind: 'info',
                    title: 'Command sent to Terminal',
                    body: 'It waits at the prompt for your review — nothing runs automatically.',
                  })
                  navigate(`/app/${instanceId}/workbench/terminal`)
                }}
              />
              <CopyButton text={proposal.command} label="Copy command" />
            </>
          }
        >
          <pre className="mt-1.5 overflow-x-auto rounded-sm bg-sunken p-2 font-mono text-xs text-foreground">{proposal.command}</pre>
        </ProposalCard>,
      )
    } else {
      cards.push(
        <ProposalCard
          key={`patch_${index}`}
          icon={FileDiff}
          title={`Proposed change — ${proposal.path}`}
          actions={
            <>
              <CardButton
                icon={FileDiff}
                label="Open as file diff"
                primary
                testId="proposal-open-diff"
                onClick={() => {
                  sendToBridge({ kind: 'patch-draft', instanceId, path: proposal.path, proposed: proposal.proposed })
                  pushToast({
                    kind: 'info',
                    title: 'Patch sent to Files',
                    body: 'It opens in the governed diff review — nothing is written automatically.',
                  })
                  navigate(`/app/${instanceId}/workbench/files`)
                }}
              />
              <CopyButton text={proposal.proposed} label="Copy patch" />
            </>
          }
        >
          <pre className="mt-1.5 max-h-32 overflow-auto rounded-sm bg-sunken p-2 font-mono text-xs text-foreground">{proposal.proposed}</pre>
        </ProposalCard>,
      )
    }
  }

  return <>{cards}</>
}

// ── The row ──────────────────────────────────────────────────────────────────

export interface MessageRowProps {
  message: ConversationMessage
  instanceId: string
  pinned: boolean
  onTogglePin: () => void
  onQuote: () => void
  /** Assistant failed/stopped → retry the response. */
  onRetryResponse: () => void
  /** Locally failed user message actions. */
  onResend: () => void
  onEdit: () => void
  onDiscard: () => void
  dense?: boolean
  /** Current search match — accent ring. */
  highlighted?: boolean
  showTimestamp?: boolean
  toolEventsExpandedDefault?: boolean
}

export const MessageRow = memo(function MessageRow({
  message,
  instanceId,
  pinned,
  onTogglePin,
  onQuote,
  onRetryResponse,
  onResend,
  onEdit,
  onDiscard,
  dense,
  highlighted,
  showTimestamp = true,
  toolEventsExpandedDefault = false,
}: MessageRowProps) {
  const isUser = message.role === 'user'
  const failedUser = isUser && message.state === 'failed'
  const failedAssistant = !isUser && message.state === 'failed'
  const stopped = !isUser && message.state === 'stopped'
  const streaming = message.state === 'streaming'

  return (
    <article
      data-testid={`message-${message.role}`}
      data-message-id={message.id}
      data-state={message.state}
      className={cn(
        'group relative scroll-mt-14',
        isUser ? 'rounded-sm border border-border bg-surface px-3 py-2' : 'border-l-2 border-border-strong pl-3',
        highlighted && 'rounded-sm outline outline-2 outline-accent',
        dense && 'px-2 py-1.5',
      )}
      aria-label={isUser ? 'Your message' : 'Assistant message'}
    >
      <header className="flex items-baseline gap-2">
        <span className="text-xs font-semibold text-foreground">{isUser ? 'You' : 'Assistant'}</span>
        {showTimestamp ? <TimeAgo date={message.createdAt} /> : null}
        {pinned ? (
          <span className="inline-flex items-center gap-1 text-xs text-foreground-tertiary">
            <Pin className="size-3" aria-hidden="true" />
            Pinned
          </span>
        ) : null}
        <span className="ml-auto flex items-center gap-0.5 opacity-0 transition-opacity duration-instant focus-within:opacity-100 group-hover:opacity-100">
          {!failedUser ? (
            <>
              <CopyButton text={message.content} label="Copy message" className="inline-flex size-7 items-center justify-center" />
              <IconAction icon={Quote} label="Quote in composer" onClick={onQuote} testId={`quote-${message.id}`} />
              <IconAction
                icon={pinned ? PinOff : Pin}
                label={pinned ? 'Unpin message' : 'Pin message'}
                onClick={onTogglePin}
                testId={`pin-${message.id}`}
              />
            </>
          ) : null}
        </span>
      </header>

      {isUser ? (
        message.content ? (
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-foreground">{message.content}</p>
        ) : null
      ) : message.content ? (
        <Markdown content={message.content} />
      ) : streaming ? (
        <p className="text-sm text-foreground-tertiary">Responding…</p>
      ) : null}

      {streaming && message.content ? (
        <span className="mt-0.5 inline-block h-4 w-1.5 animate-caret-blink bg-foreground-tertiary align-text-bottom" aria-hidden="true" />
      ) : null}

      {message.attachments.length > 0 ? (
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {message.attachments.map((a) => (
            <AttachmentChip key={a.id} attachment={a} />
          ))}
        </div>
      ) : null}

      {message.contextChips.length > 0 ? (
        <div className="mt-1.5 flex flex-wrap items-center gap-1" aria-label="Context sent with this message">
          <span className="text-xs text-foreground-tertiary">Sent with:</span>
          {message.contextChips.map((chip) => (
            <SentContextChip key={chip.id} chip={chip} />
          ))}
        </div>
      ) : null}

      <ToolEvents message={message} defaultExpanded={toolEventsExpandedDefault} />
      {!isUser ? <ProposalCards message={message} instanceId={instanceId} /> : null}

      {failedUser ? (
        <div className="mt-1.5 flex flex-wrap items-center gap-2" role="alert">
          <span className="text-xs font-medium text-status-danger">Not sent</span>
          <CardButton icon={RotateCcw} label="Retry" onClick={onResend} testId={`resend-${message.id}`} />
          <CardButton icon={Pencil} label="Edit" onClick={onEdit} testId={`edit-${message.id}`} />
          <CardButton icon={Trash2} label="Delete" onClick={onDiscard} testId={`discard-${message.id}`} />
        </div>
      ) : null}

      {failedAssistant ? (
        <div className="mt-1.5 flex flex-wrap items-center gap-2" role="alert">
          <span className="text-xs font-medium text-status-danger">Response interrupted</span>
          <CardButton icon={RotateCcw} label="Retry response" onClick={onRetryResponse} testId={`retry-response-${message.id}`} />
        </div>
      ) : null}

      {stopped ? (
        <div className="mt-1.5 flex flex-wrap items-center gap-2">
          <span className="text-xs text-foreground-tertiary">Stopped by you</span>
          <CardButton icon={RotateCcw} label="Retry response" onClick={onRetryResponse} testId={`retry-response-${message.id}`} />
        </div>
      ) : null}
    </article>
  )
})
