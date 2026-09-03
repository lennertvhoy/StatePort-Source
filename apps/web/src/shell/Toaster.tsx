/**
 * Toaster (design.md §14) — ephemeral confirmations ONLY, never the only
 * record of a failure. Token-styled (shadow-2), aria-live, auto-dismiss 6 s,
 * optional click-through route.
 */
import { CircleCheck, CircleX, Info, X } from 'lucide-react'
import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

import type { Toast } from '@/state'
import { useSessionStore } from '@/state'
import { cn } from '@/lib/utils'

const TOAST_TIMEOUT_MS = 6_000

const KIND_PRESENTATION = {
  info: { icon: Info, classes: 'text-status-informational' },
  success: { icon: CircleCheck, classes: 'text-status-success' },
  error: { icon: CircleX, classes: 'text-status-danger' },
} as const

function ToastCard({ toast }: { toast: Toast }) {
  const dismissToast = useSessionStore((s) => s.dismissToast)
  const navigate = useNavigate()
  const { icon: Icon, classes } = KIND_PRESENTATION[toast.kind]

  useEffect(() => {
    const timer = window.setTimeout(() => dismissToast(toast.id), TOAST_TIMEOUT_MS)
    return () => window.clearTimeout(timer)
  }, [toast.id, dismissToast])

  return (
    <div
      className={cn(
        'pointer-events-auto flex w-80 items-start gap-2 rounded-md border border-border bg-surface px-3 py-2 shadow-2',
        'animate-in slide-in-from-bottom-2 fade-in-0 duration-med ease-enter',
      )}
      role={toast.kind === 'error' ? 'alert' : 'status'}
      data-testid="toast"
    >
      <Icon className={cn('mt-0.5 size-4 shrink-0', classes)} aria-hidden="true" />
      <button
        type="button"
        className="min-w-0 flex-1 text-left"
        onClick={() => {
          dismissToast(toast.id)
          if (toast.route) void navigate(toast.route)
        }}
      >
        <p className="text-sm font-medium text-foreground">{toast.title}</p>
        {toast.body ? <p className="mt-0.5 text-xs text-foreground-secondary">{toast.body}</p> : null}
      </button>
      <button
        type="button"
        aria-label="Dismiss"
        onClick={() => dismissToast(toast.id)}
        className="inline-flex min-h-6 min-w-6 shrink-0 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
      >
        <X className="size-3.5" aria-hidden="true" />
      </button>
    </div>
  )
}

export function Toaster() {
  const toasts = useSessionStore((s) => s.toasts)
  if (toasts.length === 0) return null
  return (
    <div
      className="pointer-events-none fixed bottom-8 right-4 z-toast flex flex-col items-end gap-2"
      aria-live="polite"
      data-testid="toaster"
    >
      {toasts.map((toast) => (
        <ToastCard key={toast.id} toast={toast} />
      ))}
    </div>
  )
}
