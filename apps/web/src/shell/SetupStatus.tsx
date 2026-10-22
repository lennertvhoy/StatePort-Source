import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { providerClient } from '@/client/providerClient'
import { useSessionStore } from '@/state'

import { useApplications } from './data'
import { modelStateFrom, type ModelState } from './setupStatusModel'

/**
 * Plain-language setup status: the StatePort service, the AI model, and the
 * installed applications. It states what was observed and offers at most one
 * next step per line. It never describes internal checks (executables,
 * authentication phases, workers) and never infers one observation from
 * another: a reachable service does not mean a model works.
 */

function useModelState(online: boolean, revision: number): ModelState {
  // The provider read rides the shell's single service poll (the revision
  // bumps on each publication); this component owns no timer.
  const [state, setState] = useState<{ revision: number; value: ModelState } | null>(null)
  useEffect(() => {
    if (!online) return
    let alive = true
    providerClient
      .getStatus()
      .then((status) => {
        if (alive) setState({ revision, value: modelStateFrom(status) })
      })
      .catch(() => {
        if (alive) setState({ revision, value: { kind: 'unavailable', reason: 'the model status could not be read' } })
      })
    return () => {
      alive = false
    }
  }, [online, revision])
  if (!online) return { kind: 'unavailable', reason: 'the StatePort service is not reachable' }
  return state?.value ?? { kind: 'checking' }
}

const linkClass =
  'inline-flex min-h-8 items-center rounded-sm text-accent hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent'

export function SetupStatus({ includeRuntime = false }: { includeRuntime?: boolean }) {
  const status = useSessionStore((s) => s.serviceStatus)
  const revision = useSessionStore((s) => s.serviceStatusRevision)
  const { instances, loading, error } = useApplications()
  const online = status?.state === 'connected' || status?.state === 'degraded'
  const model = useModelState(online, revision)

  const service = online
    ? { text: 'Connected', note: status?.state === 'degraded' ? 'Some parts are slow or limited.' : undefined }
    : status?.state === 'offline'
      ? { text: 'Unreachable', note: 'The StatePort service is not responding.' }
      : { text: 'Checking…', note: undefined }

  const runtime = status?.runtime
  const runtimeText = !online || !runtime ? undefined : runtime.status === 'available' ? 'Running' : 'Not running'

  return (
    <section aria-label="Setup status" className="rounded-md border border-border bg-surface-2 p-3" data-testid="setup-status">
      <h2 className="text-sm font-semibold text-foreground">Setup status</h2>
      <dl className="mt-3 grid gap-3 sm:grid-cols-2">
        <div className="min-w-0">
          <dt className="text-xs font-medium text-foreground">StatePort service</dt>
          <dd className="mt-0.5 text-xs text-foreground-secondary">
            <p>{service.text}</p>
            {service.note ? <p className="mt-1 text-foreground-tertiary">{service.note}</p> : null}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs font-medium text-foreground">AI model</dt>
          <dd className="mt-0.5 text-xs text-foreground-secondary">
            {model.kind === 'checking' ? <p>Checking…</p> : null}
            {model.kind === 'not_set_up' ? <p>Not set up yet</p> : null}
            {model.kind === 'ready' ? (
              <p>
                Ready with {model.model}
                {model.checked ? '' : ' (not checked yet)'}
              </p>
            ) : null}
            {model.kind === 'unavailable' ? <p>Unavailable: {model.reason}</p> : null}
            {model.kind !== 'checking' ? (
              <Link to="/settings/models" className={linkClass}>
                {model.kind === 'not_set_up' ? 'Set up a model' : 'Open model settings'}
              </Link>
            ) : null}
          </dd>
        </div>
        {includeRuntime && runtimeText ? (
          <div className="min-w-0">
            <dt className="text-xs font-medium text-foreground">Execution runtime</dt>
            <dd className="mt-0.5 text-xs text-foreground-secondary">
              <p>{runtimeText}</p>
              <Link to="/execution-host" className={linkClass}>
                View runtime status
              </Link>
            </dd>
          </div>
        ) : null}
        <div className="min-w-0">
          <dt className="text-xs font-medium text-foreground">Applications</dt>
          <dd className="mt-0.5 text-xs text-foreground-secondary">
            <p>
              {!online || error
                ? 'Not available while the service is unreachable'
                : loading
                  ? 'Checking…'
                  : instances.length === 0
                    ? 'None yet'
                    : `${instances.length} installed`}
            </p>
            {instances.length > 0 && online && !error ? (
              <Link to="/applications" className={linkClass}>
                Open applications
              </Link>
            ) : null}
          </dd>
        </div>
      </dl>
    </section>
  )
}
