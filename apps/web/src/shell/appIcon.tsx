/**
 * Application identity tile (design.md §11): the instance glyph in a 20 px
 * rounded (4 px) --bg-active tile with a --text-secondary icon. The glyph map
 * itself lives in ./instanceGlyph.
 */
import { createElement } from 'react'

import { cn } from '@/lib/utils'

import type { ApplicationInstance } from '@/client'

import { instanceGlyph } from './instanceGlyph'

/** Glyph in a 20 px rounded (4 px) --bg-active tile with --text-secondary icon (§11). */
export function InstanceGlyphTile({
  instance,
  className,
}: {
  instance: Pick<ApplicationInstance, 'packageName' | 'name'>
  className?: string
}) {
  return (
    <span className={cn('inline-flex size-5 shrink-0 items-center justify-center rounded-sm bg-active', className)} aria-hidden="true">
      {createElement(instanceGlyph(instance), { className: 'size-3.5 text-foreground-secondary' })}
    </span>
  )
}
