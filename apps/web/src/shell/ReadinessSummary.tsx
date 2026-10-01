import { useEffect, useState } from 'react'
import { providerClient, type ProviderStatus } from '@/client/providerClient'
import { Link } from 'react-router-dom'
import { useSessionStore } from '@/state'
import { useApplications } from './data'

/** Observations are separate: reachability never establishes permission or successful work. */
export function ReadinessSummary() {
  const status = useSessionStore((s) => s.serviceStatus)
  // The provider observation rides the shell's single 30 s service poll:
  // every service-status publication bumps the revision and re-reads the
  // provider while the service is online. No second interval here.
  const serviceStatusRevision = useSessionStore((s) => s.serviceStatusRevision)
  const { instances, loading, error } = useApplications()
  const online = status?.state === 'connected' || status?.state === 'degraded'
  const runtime = online ? status?.runtime : undefined
  const [provider, setProvider] = useState<{ value?: ProviderStatus; failed: boolean } | null>(null)
  useEffect(() => {
    let alive = true
    if (!online) return
    providerClient.getStatus()
      .then((value) => { if (alive) setProvider({ value, failed: false }) })
      .catch(() => { if (alive) setProvider({ failed: true }) })
    return () => { alive = false }
  }, [online, serviceStatusRevision])
  const observation = online ? provider?.value : undefined
  const providerValue = !online ? 'Not checked while service is offline'
    : provider?.failed ? 'Status unavailable'
    : !observation ? 'Checking provider'
    : `Executable: ${observation.executableInstalled ? 'installed' : 'missing'}; configuration: ${observation.configured ? 'configured' : 'not configured'}; authentication: ${observation.authenticationStatus}; request: ${observation.requestStatus}. Quota and billing: unavailable.`
  // A readiness row may observe a gap, but it must never dead-end: each gap
  // gets one plain sentence that says what the gap means and whether the study
  // sample needs it, plus the single guided next action below. The steps mirror
  // the shipped Coding provider settings (choose OpenCode, save a model, then
  // connect an API key or sign in with OpenCode itself).
  const providerReady = Boolean(observation?.configured && observation.authenticationStatus === 'authenticated')
  const providerExplanation = !online || providerReady ? undefined
    : 'AI coding agents need an OpenCode sign-in; the study sample does not. To set up: open Coding provider, choose OpenCode, save a model, then connect an API key or sign in with OpenCode.'
  const workerReady = Boolean(runtime?.workerExecutionEnabled)
  const workerExplanation = !runtime || runtime.workerExecutionEnabled === undefined ? undefined
    : workerReady ? undefined
    : 'Worker execution runs approved tasks in the background and is off by default; the study sample works without it.'
  const checks = [
    { name: 'Local service', value: status?.state === 'connected' ? 'Connected' : status?.state === 'degraded' ? 'Degraded' : status?.state === 'offline' ? 'Offline' : 'Not checked', action: 'Review connection', to: '/settings/advanced' },
    { name: 'Execution runtime', value: !runtime ? 'Not checked' : runtime.status === 'available' ? 'Reachable' : 'Unavailable', action: 'Inspect execution host', to: '/execution-host' },
    { name: 'Worker execution', value: !runtime || runtime.workerExecutionEnabled === undefined ? 'Not checked' : runtime.workerExecutionEnabled ? 'Enabled; each task still requires authority' : 'Disabled', explanation: workerExplanation, action: 'Review execution controls', to: '/execution-host' },
    { name: 'Provider', value: providerValue, explanation: providerExplanation, action: 'Set up or verify provider', to: '/settings/provider' },
    { name: 'Applications', value: !online || error ? 'Inventory unavailable' : loading ? 'Checking inventory' : instances.length ? `${instances.length} installed; review an application before work` : 'No applications installed', action: instances.length && online && !error ? 'Review applications' : 'Import a template', to: instances.length && online && !error ? '/applications' : '/catalog' },
  ]
  return (
    <section aria-label="Workspace readiness" className="rounded-md border border-border bg-surface-2 p-3">
      <h2 className="text-sm font-semibold text-foreground">Workspace readiness</h2>
      <p className="mt-1 text-xs text-foreground-secondary">Service health alone does not confirm that a task can run. Review grants and approve requested work in the application.</p>
      <dl className="mt-3 grid gap-3 sm:grid-cols-2">
        {checks.map((check) => (
          <div key={check.name} className="min-w-0">
            <dt className="text-xs font-medium text-foreground">{check.name}</dt>
            <dd className="mt-0.5 text-xs text-foreground-secondary">
              <p>{check.value}</p>
              {'explanation' in check && typeof check.explanation === 'string' ? (
                <p className="mt-1 text-foreground-tertiary">{check.explanation}</p>
              ) : null}
              <Link to={check.to} className="mt-1 inline-flex min-h-8 items-center rounded-sm text-accent hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent">{check.action}</Link>
            </dd>
          </div>
        ))}
      </dl>
    </section>
  )
}
