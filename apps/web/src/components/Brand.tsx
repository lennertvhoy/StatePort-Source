/** StatePort's canonical block-arch mascot mark, shared by shell surfaces. */
import type { CSSProperties } from 'react'

import { cn } from '@/lib/utils'

import mascotCompact from '../../assets/brand/stateport-favicon-block-arch.svg'
import mascotLight from '../../assets/brand/stateport-mascot-light-block-arch.svg'

export type BrandMarkSize = 16 | 20 | 24 | 32 | 40

export function BrandMark({
  size = 24,
  className,
  style,
  title,
}: {
  size?: BrandMarkSize
  className?: string
  style?: CSSProperties
  /** Accessible name; omit when decorative beside a visible wordmark. */
  title?: string
}) {
  const compact = size < 40

  return (
    <span
      role={title ? 'img' : undefined}
      aria-label={title}
      aria-hidden={title ? undefined : true}
      className={cn('brand-mark inline-flex shrink-0 items-center justify-center', className)}
      style={{ width: size, height: size, ...style }}
      data-brand-size={size}
      data-testid="brand-mark"
    >
      <span className="brand-art-frame inline-flex shrink-0 items-center justify-center" aria-hidden="true">
        {compact ? (
          <img
            src={mascotCompact}
            alt=""
            aria-hidden="true"
            className="brand-mascot-compact size-full object-contain"
            data-brand-asset="compact"
          />
        ) : (
          <img
            src={mascotLight}
            alt=""
            aria-hidden="true"
            className="brand-mascot-light size-full object-contain"
            data-brand-asset="light"
          />
        )}
      </span>
    </span>
  )
}

/** Expanded source-code lockup for the application shell. */
export function BrandLockup({ className }: { className?: string }) {
  return (
    <span className={cn('brand-lockup inline-flex shrink-0 items-center gap-2 whitespace-nowrap text-foreground', className)} data-testid="brand-lockup">
      <BrandMark size={40} />
      <span className="text-[15px] font-semibold leading-none tracking-[-0.01em]">StatePort</span>
    </span>
  )
}
