/**
 * AttentionFeed — the combined, de-duplicated "Needs attention" row list
 * shared by the Applications home and the App overview (app-overview.md:
 * "same component as Applications home").
 *
 * Row kinds:
 * - pending approvals — ShieldQuestion + risk word, primary action Review;
 * - attention items — TriangleAlert + reason, primary Open, inline Acknowledge;
 * - failed operations — CircleX + recovery hint, primary Open.
 *
 * De-dup rule: an attention item that merely points at a pending approval
 * (`actionRoute` → `/approvals/:id` in the same feed) is dropped — the
 * approval row carries the richer truth (scope, risk, expiry).
 */
import { Check, CircleX, EllipsisVertical, ShieldQuestion, TriangleAlert } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

import type { AttentionItem } from '@/client'
import { TimeAgo, Tooltip } from '@/components'
import { cn } from '@/lib/utils'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

import type { AttentionFeedItem } from '../lib/attentionFeed'

export type { AttentionFeedItem } from '../lib/attentionFeed'

export interface AttentionFeedProps {
  items: AttentionFeedItem[]
  /** Acknowledge an attention item (client call lives in the page). */
  onAcknowledge?: (item: AttentionItem) => void
  /** True in read-only/offline mode — mutating actions hide (§applications States). */
  readOnly?: boolean
  className?: string
}

export function AttentionFeed({ items, onAcknowledge, readOnly = false, className }: AttentionFeedProps) {
  const navigate = useNavigate()
  return (
    <ul aria-label="Needs attention" className={cn('divide-y divide-border', className)} data-testid="attention-feed">
      {items.map((entry) => (
        <AttentionRow
          key={entry.kind === 'approval' ? `appr:${entry.approval.id}` : entry.kind === 'attention' ? `attn:${entry.item.id}` : `op:${entry.operation.id}`}
          entry={entry}
          readOnly={readOnly}
          onAcknowledge={onAcknowledge}
          onOpenInstance={(instanceId) => void navigate(`/app/${instanceId}`)}
          onOpenRoute={(route) => void navigate(route)}
        />
      ))}
    </ul>
  )
}

function AttentionRow({
  entry,
  readOnly,
  onAcknowledge,
  onOpenInstance,
  onOpenRoute,
}: {
  entry: AttentionFeedItem
  readOnly: boolean
  onAcknowledge?: (item: AttentionItem) => void
  onOpenInstance: (instanceId: string) => void
  onOpenRoute: (route: string) => void
}) {
  if (entry.kind === 'approval') {
    const { approval } = entry
    return (
      <RowShell
        icon={<ShieldQuestion className="size-4 shrink-0 text-status-waiting" aria-hidden="true" />}
        title={approval.title}
        qualifier={`${approval.risk} risk`}
        qualifierClass="text-status-waiting"
        instanceName={entry.instanceName}
        createdAt={entry.createdAt}
        primaryAction={{ label: 'Review', onClick: () => onOpenRoute(`/approvals/${approval.id}`), ariaLabel: `Review approval “${approval.title}”` }}
        menu={
          <>
            <DropdownMenuItem onSelect={() => onOpenInstance(approval.instanceId)}>Open application</DropdownMenuItem>
          </>
        }
        testId={`attention-approval-${approval.id}`}
      />
    )
  }

  if (entry.kind === 'attention') {
    const { item } = entry
    return (
      <RowShell
        icon={<TriangleAlert className="size-4 shrink-0 text-status-attention" aria-hidden="true" />}
        title={item.title}
        detail={item.detail}
        instanceName={entry.instanceName}
        createdAt={entry.createdAt}
        primaryAction={{
          label: 'Open',
          onClick: () => (item.actionRoute ? onOpenRoute(item.actionRoute) : onOpenInstance(item.instanceId)),
          ariaLabel: `Open “${item.title}”`,
        }}
        acknowledge={
          !readOnly && onAcknowledge
            ? { onClick: () => onAcknowledge(item), ariaLabel: `Acknowledge “${item.title}”` }
            : undefined
        }
        menu={
          <>
            <DropdownMenuItem onSelect={() => onOpenInstance(item.instanceId)}>Open application</DropdownMenuItem>
            {!readOnly && onAcknowledge ? (
              <DropdownMenuItem onSelect={() => onAcknowledge(item)}>Acknowledge</DropdownMenuItem>
            ) : null}
          </>
        }
        testId={`attention-item-${item.id}`}
      />
    )
  }

  const { operation } = entry
  return (
    <RowShell
      icon={<CircleX className="size-4 shrink-0 text-status-danger" aria-hidden="true" />}
      title={operation.title}
      detail={operation.error ?? 'The operation failed. Open the application for logs and recovery.'}
      instanceName={entry.instanceName}
      createdAt={entry.createdAt}
      primaryAction={{
        label: 'Open',
        onClick: () => onOpenInstance(operation.instanceId),
        ariaLabel: `Open “${operation.title}”`,
      }}
      menu={
        <>
          <DropdownMenuItem onSelect={() => onOpenInstance(operation.instanceId)}>Open application</DropdownMenuItem>
        </>
      }
      testId={`attention-operation-${operation.id}`}
    />
  )
}

function RowShell({
  icon,
  title,
  qualifier,
  qualifierClass,
  detail,
  instanceName,
  createdAt,
  primaryAction,
  acknowledge,
  menu,
  testId,
}: {
  icon: React.ReactNode
  title: string
  qualifier?: string
  qualifierClass?: string
  detail?: string
  instanceName: string
  createdAt: string
  primaryAction: { label: string; onClick: () => void; ariaLabel: string }
  acknowledge?: { onClick: () => void; ariaLabel: string }
  menu?: React.ReactNode
  testId: string
}) {
  return (
    <li className="flex min-h-row flex-wrap items-center gap-x-2 gap-y-1 px-2 py-1.5 max-md:min-h-11 md:flex-nowrap" data-testid={testId}>
      {icon}
      <div className="min-w-0 flex-1 basis-40">
        <p className="truncate text-sm font-medium text-foreground">
          {title}
          {qualifier ? (
            <span className={cn('ml-2 text-xs font-medium', qualifierClass ?? 'text-foreground-secondary')}>{qualifier}</span>
          ) : null}
        </p>
        {detail ? <p className="truncate text-xs text-foreground-secondary">{detail}</p> : null}
      </div>
      <span className="hidden w-36 truncate text-xs text-foreground-tertiary lg:inline" title={instanceName}>
        {instanceName}
      </span>
      <TimeAgo date={createdAt} className="shrink-0" />
      {acknowledge ? (
        <Tooltip content="Acknowledge">
          <button
            type="button"
            aria-label={acknowledge.ariaLabel}
            onClick={acknowledge.onClick}
            className="inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground md:min-h-8 md:min-w-8"
          >
            <Check className="size-4" aria-hidden="true" />
          </button>
        </Tooltip>
      ) : null}
      <button
        type="button"
        onClick={primaryAction.onClick}
        aria-label={primaryAction.ariaLabel}
        className="inline-flex min-h-10 items-center rounded-sm border border-border px-2.5 text-xs font-medium text-accent transition-colors duration-instant hover:bg-hover md:min-h-8"
      >
        {primaryAction.label}
      </button>
      {menu ? (
        <DropdownMenu>
          <DropdownMenuTrigger
            aria-label={`More actions for “${title}”`}
            className="inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground md:min-h-8 md:min-w-8"
          >
            <EllipsisVertical className="size-4" aria-hidden="true" />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="bg-surface">
            {menu}
          </DropdownMenuContent>
        </DropdownMenu>
      ) : null}
    </li>
  )
}
