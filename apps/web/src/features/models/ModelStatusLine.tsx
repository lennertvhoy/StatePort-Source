/**
 * The AI-model status line: one plain sentence about the model route, read
 * from `GET /v1/models`, with a link to Settings → Models.
 *
 * It never claims that a model is ready unless the service said so, and a
 * failed read says "unknown", not "off" and not "ready".
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { getModelsClient, type ModelsView } from '@/client/modelsClient'
import { Spinner } from '@/components'

type Line =
  | { kind: 'loading'; text: string }
  | { kind: 'unknown'; text: string }
  | { kind: 'ready'; text: string }
  | { kind: 'off'; text: string }

function lineFor(view: ModelsView | null, failed: boolean): Line {
  if (failed) return { kind: 'unknown', text: 'StatePort could not read its model routes.' }
  if (!view) return { kind: 'loading', text: 'Checking the model route…' }
  const route = view.routes.find((item) => item.actionClass === 'agent.edit-state')
  const model = route?.model ?? null
  if (view.status.state === 'ready' && model) {
    return { kind: 'ready', text: `Agent actions use ${model}.` }
  }
  if (view.status.state === 'not_consented') {
    return { kind: 'off', text: 'Free models are off until you accept their terms.' }
  }
  if (view.status.state === 'harness_unavailable') {
    return { kind: 'off', text: 'The model program is not available on this machine, so agent actions stay off.' }
  }
  if (view.status.state === 'no_route' || !model) {
    return { kind: 'off', text: 'No model is chosen for agent actions yet, so they stay off.' }
  }
  return { kind: 'off', text: view.status.detail || 'No model is chosen for agent actions yet.' }
}

export function ModelStatusLine() {
  const [view, setView] = useState<ModelsView | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let cancelled = false
    getModelsClient()
      .getView()
      .then((value) => {
        if (cancelled) return
        setView(value)
        setFailed(false)
      })
      .catch(() => {
        if (!cancelled) setFailed(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const line = lineFor(view, failed)
  return (
    <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-foreground-secondary" data-testid="model-status-line" data-state={line.kind}>
      <span className="font-medium text-foreground-tertiary">AI model</span>
      {line.kind === 'loading' ? (
        <Spinner size={12} label="Checking the model route…" />
      ) : null}
      <span>{line.text}</span>
      <Link to="/settings/models" className="font-medium text-accent hover:underline" data-testid="model-status-link">
        Choose AI models
      </Link>
    </p>
  )
}
