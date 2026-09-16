/**
 * Operator-authorized control-plane agent run panel.
 *
 * Readiness, the objective form, the current run projection and its bounded
 * output are all server-reported. The panel never fabricates a run identity,
 * a terminal status or a success; while the POST is unconfirmed it only says
 * "starting", and a failure is shown with the service's own code/detail.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'

import {
  agentClient,
  type AgentRun,
  type AgentRunOutput,
  type AgentStatus,
} from '@/client/agentClient'
import { ClientError } from '@/client/types'
import { Button } from '@/components/ui/button'

/** Poll cadence while a run is in flight; the service owns the run itself. */
export const AGENT_POLL_MS = 2000
/** Server contract: objective length bound. */
export const AGENT_OBJECTIVE_MAX = 256
/** Render cap for run output; the API may legitimately return more. */
export const AGENT_OUTPUT_RENDER_CAP = 64_000

function failureText(failure: unknown, fallback: string): string {
  if (failure instanceof ClientError) {
    return `${failure.code ?? 'request_failed'}: ${failure.message}`
  }
  return fallback
}

function isTerminal(status: AgentRun['status']): boolean {
  return status !== 'running'
}

function shortRunId(runId: string): string {
  return runId.length > 12 ? `${runId.slice(0, 12)}…` : runId
}

function reported(value: string | number | null | undefined): string {
  return value === null || value === undefined || value === '' ? 'not reported' : String(value)
}

function directoryFile(present: boolean): string {
  return present ? 'present' : 'missing'
}

export default function AgentRunPanel() {
  const [status, setStatus] = useState<AgentStatus | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)
  const [runs, setRuns] = useState<AgentRun[]>([])
  const [runsError, setRunsError] = useState<string | null>(null)
  const [objective, setObjective] = useState('')
  const [starting, setStarting] = useState(false)
  const [startError, setStartError] = useState<string | null>(null)
  const [currentRun, setCurrentRun] = useState<AgentRun | null>(null)
  const [runError, setRunError] = useState<string | null>(null)
  const [output, setOutput] = useState<AgentRunOutput | null>(null)
  const [outputError, setOutputError] = useState<string | null>(null)
  const [loadingOutput, setLoadingOutput] = useState(false)
  const alive = useRef(true)
  const statusGeneration = useRef(0)
  const runsGeneration = useRef(0)

  const loadStatus = useCallback(async () => {
    const generation = ++statusGeneration.current
    try {
      const next = await agentClient.getStatus()
      if (!alive.current || statusGeneration.current !== generation) return
      setStatus(next)
      setStatusError(null)
    } catch {
      if (!alive.current || statusGeneration.current !== generation) return
      setStatus(null)
      setStatusError('Agent readiness is unavailable. The service must report readiness before a run can start.')
    }
  }, [])

  const loadRuns = useCallback(async () => {
    const generation = ++runsGeneration.current
    try {
      const next = await agentClient.listRuns()
      if (!alive.current || runsGeneration.current !== generation) return
      setRuns(next)
      setRunsError(null)
    } catch {
      if (!alive.current || runsGeneration.current !== generation) return
      setRunsError('Recent agent runs could not be loaded. An accepted run is not affected by this read failure.')
    }
  }, [])

  useEffect(() => {
    alive.current = true
    void loadStatus()
    void loadRuns()
    return () => { alive.current = false }
  }, [loadRuns, loadStatus])

  const activeRunId = currentRun?.runId ?? null
  const activeRunStatus = currentRun?.status ?? null

  // Poll only while the selected run is in flight; any terminal projection
  // stops the interval. Unmount clears it through the same cleanup.
  useEffect(() => {
    if (activeRunId === null || activeRunStatus !== 'running') return
    let cancelled = false
    const poll = async () => {
      try {
        const next = await agentClient.getRun(activeRunId)
        if (cancelled) return
        setCurrentRun(next)
        setRunError(null)
        setRuns(previous => previous.map(run => run.runId === next.runId ? next : run))
        if (isTerminal(next.status)) void loadRuns()
      } catch {
        if (!cancelled) setRunError(`Run ${shortRunId(activeRunId)} could not be refreshed. The last server-reported state stays shown.`)
      }
    }
    const timer = window.setInterval(() => { void poll() }, AGENT_POLL_MS)
    return () => { cancelled = true; window.clearInterval(timer) }
  }, [activeRunId, activeRunStatus, loadRuns])

  // Fetch the bounded output once per terminal projection (or selection).
  useEffect(() => {
    if (activeRunId === null || activeRunStatus === 'running') return
    let cancelled = false
    setLoadingOutput(true)
    setOutput(null)
    setOutputError(null)
    agentClient.getOutput(activeRunId).then(value => {
      if (!cancelled) setOutput(value)
    }).catch(() => {
      if (!cancelled) setOutputError(`Output for run ${shortRunId(activeRunId)} could not be loaded.`)
    }).finally(() => {
      if (!cancelled) setLoadingOutput(false)
    })
    return () => { cancelled = true }
  }, [activeRunId, activeRunStatus])

  const trimmedObjective = objective.trim()
  const inFlight = starting || activeRunStatus === 'running'
  const ready = status?.available === true
  const canStart = ready && !inFlight && trimmedObjective.length > 0

  async function startRun(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!canStart) return
    setStarting(true)
    setStartError(null)
    setRunError(null)
    try {
      const started = await agentClient.startRun(trimmedObjective)
      if (!alive.current) return
      setCurrentRun({
        runId: started.runId,
        status: 'running',
        objective: started.objective,
        exitStatus: null,
        outputBytes: null,
        startedAt: started.startedAt,
        finishedAt: null,
        refusal: null,
      })
      setObjective('')
      void loadRuns()
    } catch (failure) {
      if (!alive.current) return
      setStartError(failureText(failure, 'The agent run could not be started; the service returned no run identity.'))
    } finally {
      if (alive.current) setStarting(false)
    }
  }

  function selectRun(run: AgentRun) {
    setStartError(null)
    setRunError(null)
    if (run.runId !== currentRun?.runId) {
      setOutput(null)
      setOutputError(null)
    }
    setCurrentRun(run)
  }

  const outputText = output?.output.slice(0, AGENT_OUTPUT_RENDER_CAP) ?? ''
  const renderTruncated = output !== null && output.output.length > AGENT_OUTPUT_RENDER_CAP

  return (
    <section aria-label="Agent run" className="space-y-3 rounded border border-border p-4">
      <h2 className="text-sm font-medium">Agent run</h2>
      <p className="text-xs text-foreground-secondary">
        Submit one bounded objective to the operator-authorized control-plane agent. The service owns readiness,
        workspace authority and execution; this panel shows only server-reported state and never starts a run while
        readiness is unavailable.
      </p>

      <div aria-label="Agent readiness" role="status" className="space-y-1 text-sm">
        {status === null && statusError === null && <p>Checking agent readiness…</p>}
        {status === null && statusError !== null && <p>{statusError}</p>}
        {status !== null && <>
          <p>Readiness: {status.available ? 'available' : 'unavailable'}</p>
          {!status.available && (status.refusals.length === 0
            ? <p>No refusal detail was reported; a run cannot be started until the service reports readiness.</p>
            : <ul className="list-disc space-y-1 pl-5">
              {status.refusals.map((refusal, index) => (
                <li key={`${refusal.reason}-${index}`}>{refusal.reason}: {refusal.detail}</li>
              ))}
            </ul>)}
          <p>
            Provider directory: {status.providerDirectory.configured ? 'configured' : 'not configured'} ·{' '}
            {status.providerDirectory.present ? 'present' : 'missing'} · files: provider env{' '}
            {directoryFile(status.providerDirectory.files.providerEnv)}, opencode.json{' '}
            {directoryFile(status.providerDirectory.files.opencodeJson)}, model{' '}
            {directoryFile(status.providerDirectory.files.model)}
          </p>
          <p>
            Workspace: {status.workspace.status}
            {status.workspace.workloadId ? ` · workload ${status.workspace.workloadId}` : ''}
          </p>
        </>}
      </div>

      <form aria-label="Start agent run" className="space-y-2" onSubmit={event => { void startRun(event) }}>
        <label htmlFor="agent-run-objective" className="block text-sm font-medium">Objective</label>
        <textarea
          id="agent-run-objective"
          value={objective}
          onChange={event => setObjective(event.target.value)}
          rows={3}
          required
          maxLength={AGENT_OBJECTIVE_MAX}
          disabled={inFlight}
          aria-describedby="agent-run-objective-help"
          className="w-full rounded-md border bg-background px-3 py-2 text-sm"
        />
        <p id="agent-run-objective-help" className="text-xs text-foreground-secondary">
          {objective.length}/{AGENT_OBJECTIVE_MAX} characters
          {objective.length > 0 && trimmedObjective.length === 0 ? ' · the objective cannot be blank' : ''}
        </p>
        <Button type="submit" size="sm" variant="outline" disabled={!canStart}>
          {starting ? 'Starting…' : 'Run agent'}
        </Button>
        {startError && <p role="alert" className="text-sm">{startError}</p>}
      </form>

      <div aria-label="Current agent run" className="space-y-2 rounded bg-surface p-3">
        <h3 className="text-xs font-semibold">Current run</h3>
        {starting && <p role="status" className="text-sm">Status: starting — waiting for the service to accept the objective.</p>}
        {!starting && currentRun === null && <p className="text-sm">No run selected. Submit an objective or select a recent run.</p>}
        {!starting && currentRun !== null && <div className="space-y-1 text-sm">
          <p>
            Status: <span data-testid="agent-run-status">{currentRun.status}</span> · Run:{' '}
            <span className="break-all font-mono">{currentRun.runId}</span>
          </p>
          <p>Objective: {currentRun.objective}</p>
          <p>
            Exit status: {reported(currentRun.exitStatus)} · Output bytes: {reported(currentRun.outputBytes)}
          </p>
          <p>Started: {reported(currentRun.startedAt)} · Finished: {reported(currentRun.finishedAt)}</p>
          {currentRun.refusal && <p role="status">Refused: {currentRun.refusal.reason}: {currentRun.refusal.detail}</p>}
          {runError && <p role="status">{runError}</p>}
        </div>}
        {loadingOutput && <p role="status">Loading run output…</p>}
        {outputError && <p role="status">{outputError}</p>}
        {output !== null && !loadingOutput && <div>
          <p className="text-xs text-foreground-secondary">
            {output.truncated
              ? `Output truncated by the service: ${output.outputBytes} bytes total.`
              : `${output.outputBytes} bytes total.`}
            {renderTruncated ? ` Showing the first ${AGENT_OUTPUT_RENDER_CAP} characters in this panel.` : ''}
          </p>
          <pre className="mt-2 max-h-64 overflow-auto rounded bg-surface p-3 text-xs" aria-label="Agent run output">{outputText}</pre>
        </div>}
      </div>

      <div aria-label="Recent agent runs" className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-xs font-semibold">Recent runs</h3>
          <Button type="button" size="sm" variant="ghost" disabled={starting} onClick={() => { void loadStatus(); void loadRuns() }}>
            Refresh agent status
          </Button>
        </div>
        {runsError && <p role="status" className="text-sm">{runsError}</p>}
        {runs.length === 0 && !runsError && <p className="text-sm">No agent runs have been recorded.</p>}
        <ul className="space-y-1">
          {runs.map(run => (
            <li key={run.runId}>
              <button
                type="button"
                aria-pressed={currentRun?.runId === run.runId}
                onClick={() => selectRun(run)}
                className="w-full rounded border border-border p-2 text-left text-xs hover:bg-surface"
              >
                <span className="font-mono">{shortRunId(run.runId)}</span> · {run.status} · {run.objective} ·
                started {reported(run.startedAt)} · finished {reported(run.finishedAt)}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}
