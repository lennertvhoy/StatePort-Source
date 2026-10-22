/**
 * The current-application context, provided by AppContextShell to every
 * app-level route. Lives outside the component module so the shell keeps a
 * clean fast-refresh boundary (component-only exports).
 */
import { createContext, useContext } from 'react'

import type { ApplicationInstance, CapabilityId, CapabilityState } from '@/client'

export interface CurrentInstanceContext {
  instance: ApplicationInstance | null
  capabilities: ReadonlyMap<CapabilityId, CapabilityState>
  loading: boolean
  error: unknown
  refresh: () => void
  /** True when the capability is available or degraded (usable). */
  hasCapability: (id: CapabilityId) => boolean
  /** Capability state for badge/dot rendering (undefined when absent). */
  capability: (id: CapabilityId) => CapabilityState | undefined
}

export const InstanceContext = createContext<CurrentInstanceContext>({
  instance: null,
  capabilities: new Map(),
  loading: true,
  error: null,
  refresh: () => undefined,
  hasCapability: () => false,
  capability: () => undefined,
})

/** THE hook feature agents use to reach the current application instance. */
export function useCurrentInstance(): CurrentInstanceContext {
  return useContext(InstanceContext)
}
