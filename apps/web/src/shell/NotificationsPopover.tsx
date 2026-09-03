/**
 * Notifications popover — durable notification items behind the Bell.
 * (Toasts are for ephemeral confirmations only; this is the record, §14.)
 */
import { Bell } from 'lucide-react'
import type { ReactNode } from 'react'
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import type { NotificationItem } from '@/client'
import { getClient } from '@/client'
import { EmptyState, TimeAgo } from '@/components'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { cn } from '@/lib/utils'
import { useSessionStore } from '@/state'

export function NotificationsPopover({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const [items, setItems] = useState<NotificationItem[] | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [retry, setRetry] = useState(0)
  const navigate = useNavigate()
  const pushToast = useSessionStore((state) => state.pushToast)

  useEffect(() => {
    if (!open) return
    let cancelled = false
    getClient()
      .activity.listNotifications()
      .then((list) => {
        if (!cancelled) setItems(list.sort((a, b) => b.createdAt.localeCompare(a.createdAt)))
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err)
          setItems(null)
        }
      })
    return () => {
      cancelled = true
    }
  }, [open, retry])

  return (
    <Popover
      open={open}
      onOpenChange={(nextOpen) => {
        setOpen(nextOpen)
        if (nextOpen) {
          setItems(null)
          setError(null)
        }
      }}
    >
      <PopoverTrigger asChild>{children}</PopoverTrigger>
      <PopoverContent side="right" align="end" sideOffset={8} className="w-80 bg-surface p-0" data-testid="notifications-popover">
        <div className="border-b border-border px-3 py-2 text-sm font-medium text-foreground">Notifications</div>
        <div className="max-h-80 overflow-y-auto">
          {error ? (
            <div className="flex flex-col items-start gap-2 px-3 py-4" data-testid="notifications-unavailable">
              <p className="text-sm font-medium text-foreground">Notifications unavailable</p>
              <p className="text-sm text-foreground-secondary">The notification source could not be read. No empty state is being inferred.</p>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setError(null)
                  setItems(null)
                  setRetry((value) => value + 1)
                }}
              >
                Retry
              </Button>
            </div>
          ) : items === null ? (
            <p className="px-3 py-4 text-sm text-foreground-secondary">Loading…</p>
          ) : items.length === 0 ? (
            <EmptyState icon={Bell} title="No notifications" description="Nothing has been reported yet. That is normal." />
          ) : (
            <ul className="flex flex-col">
              {items.map((item) => (
                <li key={item.id}>
                  <button
                    type="button"
                    className={cn(
                      'flex w-full flex-col gap-0.5 border-b border-border px-3 py-2 text-left transition-colors duration-instant hover:bg-hover',
                      !item.read && 'bg-surface-2',
                    )}
                    onClick={() => {
                      void getClient()
                        .activity.markNotificationRead(item.id, { instanceId: item.instanceId })
                        .then(() => {
                          setItems((current) =>
                            current?.map((candidate) =>
                              candidate.id === item.id
                                ? { ...candidate, read: true }
                                : candidate,
                            ) ?? null,
                          )
                        })
                        .catch(() => {
                          pushToast({
                            kind: 'error',
                            title: 'Notification was not marked read',
                            body: 'The attention item changed or could not be reached. Reload before retrying.',
                          })
                        })
                      setOpen(false)
                      if (item.route) void navigate(item.route)
                    }}
                  >
                    <span className="flex items-center gap-2">
                      {!item.read ? <span className="size-1.5 shrink-0 rounded-full bg-accent" aria-label="Unread" /> : null}
                      <span className="min-w-0 flex-1 truncate text-sm font-medium text-foreground">{item.title}</span>
                      <TimeAgo date={item.createdAt} />
                    </span>
                    {item.body ? <span className="line-clamp-2 text-xs text-foreground-secondary">{item.body}</span> : null}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </PopoverContent>
    </Popover>
  )
}
