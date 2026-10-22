/**
 * Pure first-run onboarding rules (done state comes only from service data).
 */
import type { ProviderStatus } from '@/client/providerClient'
import type { ModelsView } from '@/client/models'

/** A connected own account: configured and signed in (credential, adopted sign-in, or login). */
export function ownAccountReady(provider: ProviderStatus | null): boolean {
  if (!provider?.configured) return false
  return (
    provider.authenticationStatus === 'authenticated'
    || provider.credentialStatus === 'configured'
    || provider.adoptionStatus === 'adopted'
  )
}

/**
 * Step 1: an AI route is chosen when free-model consent is recorded or the
 * operator's own OpenCode account is connected. Consent alone is not a route:
 * a free model still has to be measured and chosen.
 */
export function aiRouteStepState(
  models: ModelsView | null,
  provider: ProviderStatus | null,
): { done: boolean; freeConsented: boolean; ownAccount: boolean; routeMeasured: boolean } {
  const freeConsented = models?.consent.state === 'granted'
  const ownAccount = ownAccountReady(provider)
  const routeMeasured = Boolean(models?.routes.find((route) => route.actionClass === 'agent.edit-state')?.model)
  // Agent actions run only on the free route in this release (an own account serves chat), so only the free
  // route's consent completes the step.
  return { done: freeConsented, freeConsented, ownAccount, routeMeasured }
}

/** Step 3: a run exists for one of the applications. */
export function firstRunDoneFromRuns(runCounts: number[]): boolean {
  return runCounts.some((count) => count > 0)
}
