import type { ProviderStatus } from '@/client/providerClient'

/** The three AI-model states a person can act on, reduced from the provider observation. */
export type ModelState =
  | { kind: 'checking' }
  | { kind: 'not_set_up' }
  | { kind: 'ready'; model: string; checked: boolean }
  | { kind: 'unavailable'; reason: string }

/** Reduce the provider observation to the three states a person can act on. */
export function modelStateFrom(status: ProviderStatus): ModelState {
  if (!status.configured || !status.model) return { kind: 'not_set_up' }
  if (!status.connected) return { kind: 'unavailable', reason: 'the model is saved but disconnected from StatePort' }
  if (status.executableStatus === 'missing') {
    return { kind: 'unavailable', reason: 'the AI runtime is not installed in this environment' }
  }
  if (status.requestStatus === 'failed') {
    return { kind: 'unavailable', reason: status.executionRefusal || status.detail || 'the last check failed' }
  }
  if (status.authenticationStatus === 'unauthenticated' || status.authenticationStatus === 'unavailable') {
    return { kind: 'unavailable', reason: 'no working sign-in or API key was found' }
  }
  return {
    kind: 'ready',
    model: status.model,
    checked: status.requestStatus === 'succeeded' || status.authenticationStatus === 'authenticated',
  }
}
