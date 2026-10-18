/**
 * TimeAgo — saved relative/absolute/both presentation, with canonical ISO and
 * an absolute tooltip. Relative displays share one minute timer.
 */
import { format, formatDistanceStrict, parseISO } from 'date-fns'
import { useSyncExternalStore } from 'react'

import { useWorkspaceStore } from '@/state'

import { cn } from '@/lib/utils'

import { Tooltip } from './Tooltip'

export interface TimeAgoProps {
  /** ISO 8601 string or Date. */
  date: string | Date
  className?: string
}

// One clock for every relative timestamp. Absolute-only pages have no interval.
const minuteListeners = new Set<() => void>()
let minuteTimer: number | null = null
let minuteNow = Date.now()
const clockSnapshot = () => minuteNow
const noClock = () => () => undefined
function subscribeMinute(listener: () => void) {
  minuteListeners.add(listener)
  if (minuteTimer === null) {
    minuteNow = Date.now()
    minuteTimer = window.setInterval(() => {
      minuteNow = Date.now()
      for (const notify of minuteListeners) notify()
    }, 60_000)
  }
  return () => {
    minuteListeners.delete(listener)
    if (minuteListeners.size === 0 && minuteTimer !== null) {
      window.clearInterval(minuteTimer)
      minuteTimer = null
    }
  }
}

export function TimeAgo({ date, className }: TimeAgoProps) {
  const parsed = typeof date === 'string' ? parseISO(date) : date
  const mode = useWorkspaceStore((state) => state.dateTimeFormat)
  const now = useSyncExternalStore(mode === 'absolute' ? noClock : subscribeMinute, clockSnapshot, clockSnapshot)
  const relative = mode === 'absolute' ? '' : formatDistanceStrict(parsed, new Date(now), { addSuffix: true })
  const absolute = format(parsed, 'PPpp')

  return (
    <Tooltip content={absolute}>
      <time dateTime={parsed.toISOString()} className={cn('tnum text-xs text-foreground-tertiary', mode === 'absolute' || mode === 'both' ? 'whitespace-normal break-words' : 'whitespace-nowrap', className)}>
        {mode === 'absolute' ? absolute : mode === 'both' ? `${relative} · ${absolute}` : relative}
      </time>
    </Tooltip>
  )
}
