/**
 * First-run onboarding on the empty Applications page: three plain steps whose
 * done state comes from the service, never from a click.
 *
 * 1. Choose an AI route: free models (consent card). Done when free-model
 *    consent is recorded: agent actions run only on that route in this release;
 *    an own OpenCode sign-in or API key serves chat. Optional: the study
 *    sample and every check work without AI.
 * 2. Create your first application: the study sample, a template import, or
 *    the catalog. Done when an application exists.
 * 3. Run its first action. Done when a run exists.
 */
import { CircleCheck, CircleDashed, GraduationCap } from 'lucide-react'
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { agentRouteReadiness, getModelsClient, type ModelsView } from '@/client/modelsClient'
import { providerClient, type ProviderStatus } from '@/client/providerClient'
import { Spinner } from '@/components'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ConsentCard } from '@/features/models/ConsentCard'
import { acceptFreeModelTerms } from '@/features/models/consent'
import { cn } from '@/lib/utils'

import { aiRouteStepState } from '../lib/onboarding'

interface AiRouteObservation {
  status: 'loading' | 'ready'
  view: ModelsView | null
  provider: ProviderStatus | null
  /** Both sources failed: the route could not be checked at all. */
  unknown: boolean
}

function useAiRoute(): AiRouteObservation & { reload: () => void } {
  const [nonce, setNonce] = useState(0)
  const [state, setState] = useState<AiRouteObservation>({ status: 'loading', view: null, provider: null, unknown: false })
  useEffect(() => {
    let cancelled = false
    void Promise.allSettled([getModelsClient().getView(), providerClient.getStatus()]).then(([view, provider]) => {
      if (cancelled) return
      setState({
        status: 'ready',
        view: view.status === 'fulfilled' ? view.value : null,
        provider: provider.status === 'fulfilled' ? provider.value : null,
        unknown: view.status === 'rejected' && provider.status === 'rejected',
      })
    })
    return () => {
      cancelled = true
    }
  }, [nonce])
  const reload = useCallback(() => setNonce((value) => value + 1), [])
  return { ...state, reload }
}

function Step({
  number,
  title,
  done,
  testId,
  children,
}: {
  number: number
  title: string
  done: boolean
  testId: string
  children: ReactNode
}) {
  return (
    <li className="flex gap-3 px-4 py-4" data-testid={testId} data-done={done ? 'true' : 'false'}>
      <span
        className={cn(
          'flex size-7 shrink-0 items-center justify-center rounded-full border text-xs font-semibold',
          done ? 'border-status-success-border bg-status-success-bg text-status-success' : 'border-border text-foreground-secondary',
        )}
        aria-hidden="true"
      >
        {done ? <CircleCheck className="size-4" /> : number}
      </span>
      <div className="flex min-w-0 flex-1 flex-col gap-2">
        <h3 className="text-sm font-semibold text-foreground">
          {title}
          <span className="sr-only">{done ? ' (done)' : ' (not done yet)'}</span>
        </h3>
        {children}
      </div>
    </li>
  )
}

export function FirstRunOnboarding({
  sampleInstalling,
  readOnly,
  hasApplications,
  firstRunDone,
  onOpenSample,
  onImport,
  onBrowse,
}: {
  sampleInstalling: boolean
  readOnly: boolean
  hasApplications: boolean
  firstRunDone: boolean
  onOpenSample: () => void
  onImport: () => void
  onBrowse: () => void
}) {
  const navigate = useNavigate()
  const route = useAiRoute()
  const [consentOpen, setConsentOpen] = useState(false)
  const [consentBusy, setConsentBusy] = useState(false)
  const [consentError, setConsentError] = useState<unknown>(null)

  const step = aiRouteStepState(route.view, route.provider)
  const consent = route.view?.consent ?? null
  const freeRouteMeasured = route.view ? agentRouteReadiness(route.view).ready : false

  const openFreeModels = () => {
    if (consent && consent.state !== 'granted') {
      setConsentError(null)
      setConsentOpen(true)
    } else {
      void navigate('/settings/models')
    }
  }

  const accept = async () => {
    if (!consent) return
    setConsentBusy(true)
    setConsentError(null)
    try {
      await acceptFreeModelTerms(consent)
      setConsentOpen(false)
    } catch (error: unknown) {
      setConsentError(error)
    } finally {
      setConsentBusy(false)
      route.reload()
    }
  }

  return (
    <section aria-labelledby="first-run-heading" className="rounded-md border border-border bg-surface" data-testid="first-run-onboarding">
      <header className="flex items-start gap-3 border-b border-border px-4 py-4">
        <GraduationCap className="mt-0.5 size-5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
        <div className="min-w-0">
          <h2 id="first-run-heading" className="text-lg text-foreground">No applications yet</h2>
          <p className="mt-0.5 text-sm text-foreground-secondary">
            Three steps to a working application. The first is optional: the study sample and every check work without AI.
          </p>
        </div>
      </header>
      <ol className="divide-y divide-border">
        <Step number={1} title="Choose an AI route" done={step.done} testId="onboarding-step-route">
          {route.status === 'loading' ? (
            <Spinner size={12} label="Checking the AI route…" />
          ) : step.done ? (
            <p className="text-xs text-foreground-secondary" data-testid="onboarding-route-state">
              Free models allowed.
              {step.ownAccount ? ' Chat can also use your own OpenCode account.' : ''}
              {!freeRouteMeasured ? (
                <>
                  {' '}No free model has been measured yet;{' '}
                  <Link to="/settings/models" className="font-medium text-accent hover:underline">evaluate one on Settings → Models</Link>.
                </>
              ) : null}
            </p>
          ) : (
            <>
              <p className="text-xs text-foreground-secondary" data-testid="onboarding-route-state">
                {route.unknown
                  ? 'StatePort could not check its AI route right now.'
                  : 'Agent actions use OpenCode’s free models (no account); allow them here. Chat can also use your own OpenCode sign-in or API key.'}
              </p>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" disabled={readOnly} onClick={openFreeModels} data-testid="onboarding-free-models">
                  Use free models (no account)
                </Button>
                <Button size="sm" variant="ghost" onClick={() => void navigate('/settings/provider')} data-testid="onboarding-own-account">
                  For chat: connect your own OpenCode sign-in or API key
                </Button>
              </div>
            </>
          )}
        </Step>
        <Step number={2} title="Create your first application" done={hasApplications} testId="onboarding-step-app">
          <p className="text-xs text-foreground-secondary">
            The study sample is a complete governed application that works without any AI or worker setup.
          </p>
          {!readOnly ? (
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={onOpenSample} disabled={sampleInstalling}>
                {sampleInstalling ? 'Preparing the study sample' : 'Open the study sample'}
              </Button>
              <Button size="sm" variant="outline" onClick={onImport} aria-describedby="onboarding-import-help">
                Import a template
              </Button>
              <Button size="sm" variant="ghost" onClick={onBrowse}>
                Browse catalog
              </Button>
            </div>
          ) : null}
          <p id="onboarding-import-help" className="text-xs text-foreground-tertiary">
            Import ProjectState, StudyState, or any public Git repository that follows the template contract.
          </p>
        </Step>
        <Step number={3} title="Run its first action" done={firstRunDone} testId="onboarding-step-run">
          <p className="flex items-center gap-1.5 text-xs text-foreground-secondary">
            {!hasApplications ? <CircleDashed className="size-3.5 shrink-0" aria-hidden="true" /> : null}
            {hasApplications
              ? 'Open the application and press Run on one of its actions. Checks run on this machine; agent actions use the route from step 1 and come back as a change for you to review.'
              : 'After step 2: open the application and press Run on one of its actions.'}
          </p>
        </Step>
      </ol>

      <Dialog open={consentOpen} onOpenChange={(open) => { if (!consentBusy) setConsentOpen(open) }}>
        <DialogContent className="max-w-xl p-0" showCloseButton={!consentBusy}>
          <DialogTitle className="sr-only">Use free models</DialogTitle>
          <DialogDescription className="sr-only">Review the free-model terms before accepting.</DialogDescription>
          {consent ? (
            <ConsentCard
              consent={consent}
              busy={consentBusy}
              error={consentError}
              headingId="onboarding-consent-heading"
              onAccept={() => void accept()}
              onDecline={() => setConsentOpen(false)}
            />
          ) : null}
        </DialogContent>
      </Dialog>
    </section>
  )
}
