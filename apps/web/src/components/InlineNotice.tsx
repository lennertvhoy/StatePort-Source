/**
 * InlineNotice / Banner (design.md §7.3.3) — full-width contextual strip:
 * icon + text + optional action. Used for "why" explanations at the point of
 * decision. Radius 4 px, 1 px tint border. Icon + text — never color-only.
 */
import type { LucideIcon } from 'lucide-react'
import { Info, OctagonX, TriangleAlert, CircleX } from 'lucide-react'
import type { ReactNode } from 'react'

import type { SemanticState } from '@/client'
import { cn } from '@/lib/utils'

type NoticeTone = Extract<SemanticState, 'informational' | 'attention' | 'danger' | 'blocked'>

const TONE_CLASSES: Record<NoticeTone, string> = {
  informational: 'border-status-informational-border bg-status-informational-bg text-status-informational',
  attention: 'border-status-attention-border bg-status-attention-bg text-status-attention',
  danger: 'border-status-danger-border bg-status-danger-bg text-status-danger',
  blocked: 'border-status-blocked-border bg-status-blocked-bg text-status-blocked',
}

const TONE_ICONS: Record<NoticeTone, LucideIcon> = {
  informational: Info,
  attention: TriangleAlert,
  danger: CircleX,
  blocked: OctagonX,
}

export interface InlineNoticeProps {
  tone?: NoticeTone
  icon?: LucideIcon
  title?: string
  children: ReactNode
  action?: ReactNode
  className?: string
}

export function InlineNotice({ tone = 'informational', icon, title, children, action, className }: InlineNoticeProps) {
  const Icon = icon ?? TONE_ICONS[tone]
  return (
    <div
      className={cn('flex items-start gap-2 rounded-sm border px-3 py-2', TONE_CLASSES[tone], className)}
      role={tone === 'danger' ? 'alert' : 'note'}
      data-testid="inline-notice"
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        {title ? <p className="text-sm font-medium">{title}</p> : null}
        <div className="text-sm">{children}</div>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  )
}
