/**
 * DetailsPanel — the conversation's honest metadata surface (conversation.md):
 * channels, delivery state, identity, retention, pending approvals, related
 * receipts, context policy, pinned messages, and exact technical metadata.
 * Renders inline on wide screens and inside a Drawer on narrow ones.
 */
import { Pin, ShieldQuestion } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import type { Approval, Conversation, ConversationMessage, Receipt } from '@/client'
import { getClient } from '@/client'
import { CopyButton, Disclosure, SectionHeader, StatusDot, TimeAgo } from '@/components'
import { applicationDestinationAvailable } from '@/features/application-experience/registry'
import { sendToBridge } from '@/features/bridge/bridgeStore'
import { useCurrentInstance } from '@/shell/currentInstance'

// ── Small building blocks ────────────────────────────────────────────────────

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1">
      <span className="shrink-0 text-xs text-foreground-secondary">{label}</span>
      <span className="min-w-0 text-right text-xs text-foreground">{children}</span>
    </div>
  )
}

function deliveryPresentation(state: Conversation['deliveryState']): { state: 'success' | 'neutral' | 'attention' | 'danger'; label: string } {
  switch (state) {
    case 'delivered':
      return { state: 'success', label: 'Delivered' }
    case 'pending':
      return { state: 'attention', label: 'Pending' }
    case 'failed':
      return { state: 'danger', label: 'Delivery failed' }
    default:
      return { state: 'neutral', label: 'Not configured' }
  }
}

export interface DetailsPanelProps {
  instanceId: string
  conversation: Conversation | null
  messages: ConversationMessage[]
  pinnedIds: string[]
  onJumpToMessage: (messageId: string) => void
}

export function DetailsPanel({ instanceId, conversation, messages, pinnedIds, onJumpToMessage }: DetailsPanelProps) {
  const [approvals, setApprovals] = useState<Approval[] | null>(null)
  const [receipts, setReceipts] = useState<Receipt[] | null>(null)
  const { instance, hasCapability } = useCurrentInstance()
  const receiptBaseRoute = instance && applicationDestinationAvailable(instance, 'receipts')
    ? `/app/${instance.id}/receipts`
    : null

  useEffect(() => {
    let cancelled = false
    getClient()
      .approvals.list({ instanceId, status: 'pending' })
      .then((list) => {
        if (!cancelled) setApprovals(list)
      })
      .catch(() => {
        if (!cancelled) setApprovals([])
      })
    getClient()
      // Skip the goal-execution poll when the instance projection already
      // shows no effective CTO capability; the service refuses it (403).
      .receipts.list({ instanceId, goalExecution: hasCapability('cto_orchestration') })
      .then((list) => {
        if (cancelled) return
        const related = conversation
          ? list.filter((r) => r.relatedConversationId === conversation.id || r.eventKind.startsWith('conversation.'))
          : []
        setReceipts(related.slice(0, 6))
      })
      .catch(() => {
        if (!cancelled) setReceipts([])
      })
    return () => {
      cancelled = true
    }
  }, [instanceId, conversation, hasCapability])

  const delivery = deliveryPresentation(conversation?.deliveryState ?? 'not_configured')
  const channelWord = conversation?.channel === 'telegram' ? 'Telegram' : 'Web'
  const pinnedMessages = messages.filter((m) => pinnedIds.includes(m.id))

  return (
    <div className="flex flex-col gap-4 text-sm" data-testid="conversation-details">
      <section>
        <SectionHeader title="Channels" />
        <Row label="Web">
          <StatusDot state="success" label="Connected" />
        </Row>
        <Row label="Telegram">
          <StatusDot state="neutral" label="Not configured" />
        </Row>
        <Row label="Delivery">
          <StatusDot state={delivery.state} label={`${channelWord} · ${delivery.label}`} />
        </Row>
      </section>

      <section>
        <SectionHeader title="Conversation" />
        <Row label="Identity">
          <span className="inline-flex items-center gap-1">
            <span className="tnum font-mono">{conversation ? conversation.id : '—'}</span>
            {conversation ? <CopyButton text={conversation.id} label="Copy conversation id" /> : null}
          </span>
        </Row>
        <Row label="Messages">
          <span className="tnum font-mono">{messages.length}</span>
        </Row>
        <Row label="Retention">{conversation?.retentionNote ?? 'History is kept on this machine until you clear it.'}</Row>
      </section>

      <section>
        <SectionHeader title="Pending approvals" />
        {approvals === null ? (
          <p className="py-1 text-xs text-foreground-tertiary">Loading…</p>
        ) : approvals.length === 0 ? (
          <p className="py-1 text-xs text-foreground-tertiary">None pending for this application.</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {approvals.map((approval) => (
              <li key={approval.id}>
                <Link
                  to={`/approvals/${approval.id}`}
                  className="flex items-center gap-1.5 rounded-sm px-1 py-1 text-xs text-foreground hover:bg-hover"
                >
                  <ShieldQuestion className="size-3.5 shrink-0 text-status-waiting" aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate">{approval.title}</span>
                  <TimeAgo date={approval.requestedAt} />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <SectionHeader title="Related receipts" />
        {receipts === null ? (
          <p className="py-1 text-xs text-foreground-tertiary">Loading…</p>
        ) : !receiptBaseRoute ? (
          <p data-testid="conversation-receipts-unavailable" className="py-1 text-xs text-foreground-tertiary">
            Receipts are unavailable for this application experience.
          </p>
        ) : receipts.length === 0 ? (
          <p className="py-1 text-xs text-foreground-tertiary">Exports and other conversation actions record receipts here.</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {receipts.map((receipt) => (
              <li key={receipt.id}>
                <Link
                  to={`${receiptBaseRoute}/${receipt.id}`}
                  onClick={() => sendToBridge({ kind: 'receipt', instanceId, receiptId: receipt.id })}
                  className="flex items-center gap-1.5 rounded-sm px-1 py-1 text-xs text-foreground hover:bg-hover"
                >
                  <span className="min-w-0 flex-1 truncate">{receipt.actionName}</span>
                  <TimeAgo date={receipt.createdAt} />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>

      {pinnedMessages.length > 0 ? (
        <section>
          <SectionHeader title="Pinned messages" />
          <ul className="flex flex-col gap-1">
            {pinnedMessages.map((message) => (
              <li key={message.id}>
                <button
                  type="button"
                  className="flex w-full items-center gap-1.5 rounded-sm px-1 py-1 text-left text-xs text-foreground hover:bg-hover"
                  onClick={() => onJumpToMessage(message.id)}
                >
                  <Pin className="size-3 shrink-0 text-foreground-tertiary" aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate">{message.content || '(no text)'}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section>
        <SectionHeader title="Context policy" />
        <p className="py-1 text-xs leading-relaxed text-foreground-secondary">
          The assistant only sees what the context chips show: this application, anything you explicitly attach, and
          your message. Unselected files, full terminal transcripts, credentials, and other applications are never
          included.{' '}
          <Link to="/settings/privacy" className="text-accent underline underline-offset-2">
            Privacy settings
          </Link>
        </p>
      </section>

      <section>
        <Disclosure title="Technical metadata" className="rounded-md border border-border bg-surface-2">
          <dl className="flex flex-col gap-1 px-3 pb-3 pt-1 font-mono text-xs text-foreground-secondary">
            <div className="flex justify-between gap-2">
              <dt>conversation.id</dt>
              <dd className="tnum truncate">{conversation?.id ?? '—'}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt>instance.id</dt>
              <dd className="tnum truncate">{instanceId}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt>channel</dt>
              <dd>{conversation?.channel ?? '—'}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt>delivery.state</dt>
              <dd>{conversation?.deliveryState ?? '—'}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt>created</dt>
              <dd className="tnum">{conversation ? new Date(conversation.createdAt).toISOString() : '—'}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt>updated</dt>
              <dd className="tnum">{conversation ? new Date(conversation.updatedAt).toISOString() : '—'}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt>adapter</dt>
              <dd>{getClient().adapter}</dd>
            </div>
          </dl>
        </Disclosure>
      </section>
    </div>
  )
}
