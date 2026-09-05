import { X } from 'lucide-react'
import { ReadinessSummary } from '@/shell/ReadinessSummary'

export function OnboardingStrip({ onDismiss }: { onDismiss: () => void }) {
  return (
    <div className="relative" data-testid="onboarding-strip">
      <ReadinessSummary />
      <button type="button" onClick={onDismiss} aria-label="Dismiss getting started" className="absolute right-2 top-1 inline-flex min-h-10 min-w-10 items-center justify-center rounded-sm text-foreground-secondary hover:bg-hover focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent">
        <X className="size-4" aria-hidden="true" />
      </button>
    </div>
  )
}
