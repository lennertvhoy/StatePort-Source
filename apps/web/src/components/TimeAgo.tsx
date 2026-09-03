/**
 * TimeAgo (design.md §14) — relative time with the absolute timestamp in a
 * tooltip; mono tabular figures (§1 voice rules). Updates once a minute.
 */
import { format, formatDistanceToNowStrict, parseISO } from 'date-fns'
import { useEffect, useState } from 'react'

import { cn } from '@/lib/utils'

import { Tooltip } from './Tooltip'

export interface TimeAgoProps {
  /** ISO 8601 string or Date. */
  date: string | Date
  className?: string
}

export function TimeAgo({ date, className }: TimeAgoProps) {
  const parsed = typeof date === 'string' ? parseISO(date) : date
  const [, setTick] = useState(0)

  useEffect(() => {
    const timer = window.setInterval(() => setTick((t) => t + 1), 60_000)
    return () => window.clearInterval(timer)
  }, [])

  const relative = formatDistanceToNowStrict(parsed, { addSuffix: true })
  const absolute = format(parsed, 'PPpp')

  return (
    <Tooltip content={absolute}>
      <time dateTime={parsed.toISOString()} className={cn('tnum whitespace-nowrap text-xs text-foreground-tertiary', className)}>
        {relative}
      </time>
    </Tooltip>
  )
}
