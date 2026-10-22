/**
 * CopyButton (design.md §14) — copies text to the clipboard, shows a check
 * for 1.2 s as feedback. Icon-only by default (always with accessible name).
 */
import { Check, Copy } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

import { copyText } from '@/lib/clipboard'
import { cn } from '@/lib/utils'

import { Tooltip } from './Tooltip'

export interface CopyButtonProps {
  text: string
  /** Accessible name, e.g. "Copy receipt ID". */
  label?: string
  className?: string
}

export function CopyButton({ text, label = 'Copy', className }: CopyButtonProps) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<number | null>(null)

  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current)
    },
    [],
  )

  return (
    <Tooltip content={copied ? 'Copied' : label}>
      <button
        type="button"
        aria-label={label}
        className={cn(
          'inline-flex min-h-6 min-w-6 items-center justify-center rounded-sm p-1 text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground',
          className,
        )}
        onClick={async () => {
          const ok = await copyText(text)
          if (!ok) return
          setCopied(true)
          if (timer.current !== null) window.clearTimeout(timer.current)
          timer.current = window.setTimeout(() => setCopied(false), 1200)
        }}
        data-testid="copy-button"
      >
        {copied ? (
          <Check className="size-3.5 text-status-success" aria-hidden="true" />
        ) : (
          <Copy className="size-3.5" aria-hidden="true" />
        )}
      </button>
    </Tooltip>
  )
}
