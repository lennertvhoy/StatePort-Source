/**
 * CapabilityDot (design.md §7.2) — capability status marker for tabs/rows.
 * `available` renders nothing (no green "available" pills — §7.2); degraded /
 * environment-gated / unavailable render a dot with an explanatory tooltip.
 */
import type { CapabilityStatus } from '@/client'
import { capabilityPresentation } from '@/semantic'

import { StatusDot } from './StatusDot'

export interface CapabilityDotProps {
  status: CapabilityStatus
  /** Plain-language explanation shown in the tooltip for non-available states. */
  reason?: string
  className?: string
}

export function CapabilityDot({ status, reason, className }: CapabilityDotProps) {
  const presentation = capabilityPresentation(status)
  if (!presentation) return null
  const label = reason ? `${presentation.label} — ${reason}` : presentation.label
  return <StatusDot state={presentation.state} label={label} showLabel={false} className={className} />
}
