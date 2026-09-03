/**
 * OnboardingStrip — the quiet first-run strip (applications.md States):
 * at most three steps (service check → install a sample → learn approvals),
 * one dismissible row, never a modal tour and never a hero.
 */
import { Package, PlugZap, ShieldCheck, X } from 'lucide-react'
import { Link } from 'react-router-dom'

import { cn } from '@/lib/utils'
import { useSessionStore } from '@/state'

export function OnboardingStrip({ onDismiss }: { onDismiss: () => void }) {
  const serviceState = useSessionStore((s) => s.serviceStatus?.state ?? 'unknown')
  const serviceOk = serviceState === 'connected'

  const steps = [
    {
      icon: PlugZap,
      label: serviceOk ? 'Local service connected' : 'Local service check pending',
      done: serviceOk,
      to: undefined as string | undefined,
    },
    { icon: Package, label: 'Install a reviewed sample', done: false, to: '/catalog' as string | undefined },
    { icon: ShieldCheck, label: 'Learn how approvals work', done: false, to: '/approvals' as string | undefined },
  ]

  return (
    <div
      className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-md border border-border bg-surface-2 px-3 py-2"
      data-testid="onboarding-strip"
    >
      <span className="text-xs font-medium text-foreground-secondary">Get started:</span>
      <ol className="flex flex-wrap items-center gap-x-4 gap-y-1">
        {steps.map((step, i) => {
          const content = (
            <>
              <step.icon
                className={cn('size-3.5', step.done ? 'text-status-success' : 'text-foreground-tertiary')}
                aria-hidden="true"
              />
              <span className={cn(step.done && 'text-foreground-tertiary line-through')}>
                {i + 1}. {step.label}
              </span>
            </>
          )
          return (
            <li key={step.label} className="text-xs text-foreground-secondary">
              {step.to ? (
                <Link to={step.to} className="inline-flex items-center gap-1.5 rounded-sm text-accent hover:underline">
                  {content}
                </Link>
              ) : (
                <span className="inline-flex items-center gap-1.5">{content}</span>
              )}
            </li>
          )
        })}
      </ol>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss getting started"
        className="ml-auto inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground md:min-h-7 md:min-w-7"
      >
        <X className="size-4" aria-hidden="true" />
      </button>
    </div>
  )
}
