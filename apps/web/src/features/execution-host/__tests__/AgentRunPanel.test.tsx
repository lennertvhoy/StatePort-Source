/**
 * Control-plane agent run panel: server-reported readiness, submit, polling
 * to a terminal projection, bounded output, refusal handling and cleanup.
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { act } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import {
  agentClient,
  type AgentRunStarted,
  type AgentStatus,
} from '@/client/agentClient'
import { ClientError } from '@/client/types'
import AgentRunPanel, {
  AGENT_OUTPUT_RENDER_CAP,
  AGENT_POLL_MS,
} from '../AgentRunPanel'

vi.mock('@/client/agentClient', () => ({
  agentClient: {
    getStatus: vi.fn(),
    listRuns: vi.fn(),
    getRun: vi.fn(),
    getOutput: vi.fn(),
    startRun: vi.fn(),
  },
}))

const readyStatus: AgentStatus = {
  available: true,
  refusals: [],
  providerDirectory: {
    configured: true,
    present: true,
    files: { providerEnv: true, opencodeJson: true, model: true },
  },
  workspace: { status: 'available', workloadId: 'w15c-agent' },
}

const unavailableStatus: AgentStatus = {
  available: false,
  refusals: [{ reason: 'provider_directory_missing', detail: 'The sealed provider directory has not been mounted.' }],
  providerDirectory: {
    configured: false,
    present: false,
    files: { providerEnv: false, opencodeJson: false, model: false },
  },
  workspace: { status: 'unavailable', workloadId: null },
}

const runningStart: AgentRunStarted = {
  runId: 'run-1',
  status: 'running',
  objective: 'Summarize the release notes',
  workspaceId: 'w15c-agent',
  startedAt: '2026-09-15T15:00:00Z',
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(agentClient.getStatus).mockResolvedValue(readyStatus)
  vi.mocked(agentClient.listRuns).mockResolvedValue([])
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

it('starts a run, polls to completion and renders the server output', async () => {
  const interval = vi.spyOn(window, 'setInterval')
  vi.mocked(agentClient.startRun).mockResolvedValue(runningStart)
  vi.mocked(agentClient.getRun).mockResolvedValue({
    runId: 'run-1',
    status: 'completed',
    objective: 'Summarize the release notes',
    exitStatus: 0,
    outputBytes: 16,
    startedAt: '2026-09-15T15:00:00Z',
    finishedAt: '2026-09-15T15:00:05Z',
    refusal: null,
  })
  vi.mocked(agentClient.getOutput).mockResolvedValue({
    runId: 'run-1',
    output: 'release complete',
    truncated: false,
    outputBytes: 16,
  })

  render(<AgentRunPanel />)
  const textarea = await screen.findByLabelText('Objective')
  fireEvent.change(textarea, { target: { value: '  Summarize the release notes  ' } })
  expect(screen.getByText(/\d+\/256 characters/)).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Run agent' }))

  await waitFor(() => expect(agentClient.startRun).toHaveBeenCalledExactlyOnceWith('Summarize the release notes'))
  expect((await screen.findByTestId('agent-run-status')).textContent).toBe('running')
  expect(screen.getByText('Readiness: available')).toBeTruthy()
  expect(interval).toHaveBeenCalledWith(expect.any(Function), AGENT_POLL_MS)

  const poll = interval.mock.calls[interval.mock.calls.length - 1]?.[0] as () => void
  await act(async () => { poll(); await Promise.resolve(); await Promise.resolve() })

  expect((await screen.findByTestId('agent-run-status')).textContent).toBe('completed')
  expect(await screen.findByText('release complete')).toBeTruthy()
  expect(screen.getByText('16 bytes total.')).toBeTruthy()
  expect(screen.getByText(/Finished: 2026-09-15T15:00:05Z/)).toBeTruthy()
})

it('shows the exact refusal and keeps the run button disabled when unavailable', async () => {
  vi.mocked(agentClient.getStatus).mockResolvedValue(unavailableStatus)
  render(<AgentRunPanel />)

  expect(await screen.findByText('Readiness: unavailable')).toBeTruthy()
  expect(screen.getByText(/provider_directory_missing: The sealed provider directory has not been mounted\./)).toBeTruthy()
  expect(screen.getByText(/files: provider env missing, opencode\.json missing, model missing/)).toBeTruthy()

  fireEvent.change(screen.getByLabelText('Objective'), { target: { value: 'do work' } })
  expect(screen.getByRole('button', { name: 'Run agent' })).toHaveProperty('disabled', true)
  fireEvent.click(screen.getByRole('button', { name: 'Run agent' }))
  expect(agentClient.startRun).not.toHaveBeenCalled()
})

it('requires a trimmed non-empty objective and reports the counter', async () => {
  render(<AgentRunPanel />)
  const button = await screen.findByRole('button', { name: 'Run agent' })
  expect(button).toHaveProperty('disabled', true)
  fireEvent.change(screen.getByLabelText('Objective'), { target: { value: '   ' } })
  expect(button).toHaveProperty('disabled', true)
  expect(screen.getByText(/the objective cannot be blank/)).toBeTruthy()
  fireEvent.change(screen.getByLabelText('Objective'), { target: { value: 'do work' } })
  expect(button).toHaveProperty('disabled', false)
})

it('shows a POST refusal from the service without fabricating a run', async () => {
  vi.mocked(agentClient.startRun).mockRejectedValue(new ClientError(
    'http',
    'The operator did not authorize this agent run.',
    { code: 'agent_run_not_authorized', status: 403 },
  ))
  render(<AgentRunPanel />)
  fireEvent.change(await screen.findByLabelText('Objective'), { target: { value: 'do work' } })
  fireEvent.click(screen.getByRole('button', { name: 'Run agent' }))

  const alert = await screen.findByRole('alert')
  expect(alert.textContent).toContain('agent_run_not_authorized: The operator did not authorize this agent run.')
  expect(screen.getByText(/No run selected/)).toBeTruthy()
  expect(screen.queryByTestId('agent-run-status')).toBeNull()
})

it('disables the objective and button while the POST is in flight and shows starting', async () => {
  let resolveStart!: (value: AgentRunStarted) => void
  vi.mocked(agentClient.startRun).mockImplementation(() => new Promise(resolve => { resolveStart = resolve }))
  render(<AgentRunPanel />)
  const textarea = await screen.findByLabelText('Objective')
  fireEvent.change(textarea, { target: { value: 'long objective' } })
  fireEvent.click(screen.getByRole('button', { name: 'Run agent' }))

  expect(await screen.findByText(/Status: starting — waiting for the service/)).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Starting…' })).toHaveProperty('disabled', true)
  expect(textarea).toHaveProperty('disabled', true)

  await act(async () => {
    resolveStart({ ...runningStart, runId: 'run-2', objective: 'long objective' })
  })
  expect((await screen.findByTestId('agent-run-status')).textContent).toBe('running')
  expect(screen.getByRole('button', { name: 'Run agent' })).toHaveProperty('disabled', true)
})

it('labels truncated output honestly and caps the rendered block', async () => {
  vi.mocked(agentClient.listRuns).mockResolvedValue([{
    runId: 'run-3',
    status: 'completed',
    objective: 'read the whole thing',
    exitStatus: 0,
    outputBytes: 200_000,
    startedAt: '2026-09-15T15:00:00Z',
    finishedAt: '2026-09-15T15:00:10Z',
    refusal: null,
  }])
  vi.mocked(agentClient.getOutput).mockResolvedValue({
    runId: 'run-3',
    output: 'x'.repeat(AGENT_OUTPUT_RENDER_CAP + 5000),
    truncated: true,
    outputBytes: 200_000,
  })
  render(<AgentRunPanel />)

  fireEvent.click(await screen.findByRole('button', { name: /run-3/ }))
  expect(await screen.findByText(/Output truncated by the service: 200000 bytes total\./)).toBeTruthy()
  const output = await screen.findByLabelText('Agent run output')
  expect(output.textContent).toHaveLength(AGENT_OUTPUT_RENDER_CAP)
  expect(screen.getByText(new RegExp(`Showing the first ${AGENT_OUTPUT_RENDER_CAP} characters`))).toBeTruthy()
})

it('clears the status poll when the panel unmounts', async () => {
  const interval = vi.spyOn(window, 'setInterval')
  const clear = vi.spyOn(window, 'clearInterval')
  vi.mocked(agentClient.startRun).mockResolvedValue({ ...runningStart, runId: 'run-4' })
  vi.mocked(agentClient.getRun).mockResolvedValue({
    runId: 'run-4',
    status: 'running',
    objective: runningStart.objective,
    startedAt: runningStart.startedAt,
  })
  const view = render(<AgentRunPanel />)
  fireEvent.change(await screen.findByLabelText('Objective'), { target: { value: 'stay running' } })
  fireEvent.click(screen.getByRole('button', { name: 'Run agent' }))
  expect((await screen.findByTestId('agent-run-status')).textContent).toBe('running')
  await waitFor(() => expect(interval).toHaveBeenCalled())
  const timer = interval.mock.results[interval.mock.results.length - 1]?.value

  view.unmount()
  expect(clear.mock.calls.map(call => call[0])).toContain(timer)
})
