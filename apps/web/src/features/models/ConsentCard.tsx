/**
 * Free-model consent (ADR-0007 §5, keep-up-loop.md "UI"): names what leaves
 * the machine and quotes the provider's free-period terms verbatim. Accept
 * records consent bound to the terms digest; Not now sends nothing.
 */
import { ExternalLink, ShieldCheck } from 'lucide-react'

import type { ModelConsent } from '@/client/modelsClient'
import { InlineNotice } from '@/components'
import { Button } from '@/components/ui/button'

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

export function ConsentCard({
  consent,
  busy,
  error,
  onAccept,
  onDecline,
  headingId = 'free-models-consent-heading',
}: {
  consent: ModelConsent
  busy: boolean
  error?: unknown
  onAccept: () => void
  onDecline: () => void
  headingId?: string
}) {
  const provider = consent.terms.provider
  return (
    <section
      aria-labelledby={headingId}
      className="flex flex-col gap-3 rounded-md border border-border bg-surface p-4"
      data-testid="consent-card"
    >
      <div className="flex items-start gap-2">
        <ShieldCheck className="mt-0.5 size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
        <div className="min-w-0">
          <h2 id={headingId} className="text-base font-semibold text-foreground">
            Use free models without an account?
          </h2>
          <p className="mt-1 text-sm text-foreground-secondary">
            When you run an agent action, StatePort sends a copy of that application's files and the action's
            instructions to {provider}. Practice tasks that StatePort uses to score models are sent there too. Your
            other applications and StatePort's own data stay on this machine.
          </p>
        </div>
      </div>

      <div>
        <p className="text-xs font-medium text-foreground-secondary">The provider's terms, exactly as recorded</p>
        <blockquote
          className="mt-1 max-h-56 overflow-auto whitespace-pre-wrap break-words rounded-sm border border-border bg-sunken px-3 py-2 text-sm text-foreground"
          data-testid="consent-terms"
        >
          {consent.terms.text}
        </blockquote>
        {consent.terms.url ? (
          <a
            href={consent.terms.url}
            target="_blank"
            rel="noreferrer"
            className="mt-1 inline-flex min-h-8 items-center gap-1 text-xs font-medium text-accent hover:underline"
          >
            Read the provider's terms page
            <ExternalLink className="size-3" aria-hidden="true" />
          </a>
        ) : null}
      </div>

      <p className="text-xs text-foreground-tertiary">
        You can withdraw this at any time on Settings → Models. Without it, StatePort still works fully without AI
        (checks, the study sample, backups); agent actions need the free models in this release, and chat can use your
        own OpenCode sign-in or API key instead.
      </p>

      {error ? (
        <InlineNotice tone="danger" title="Consent was not recorded">
          {message(error)}
        </InlineNotice>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <Button disabled={busy} onClick={onAccept} data-testid="consent-accept">
          {busy ? 'Recording…' : 'Accept'}
        </Button>
        <Button variant="ghost" disabled={busy} onClick={onDecline} data-testid="consent-decline">
          Not now
        </Button>
      </div>
    </section>
  )
}
