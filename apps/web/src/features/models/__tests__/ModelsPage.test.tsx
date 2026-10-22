import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it } from 'vitest'

import { setModelsClientForTests } from '@/client/modelsClient'
import { ClientError } from '@/client/types'

import ModelsPage from '../ModelsPage'
import {
  FREE,
  OTHER_FREE,
  TERMS,
  TERMS_SHA,
  consentedProjection,
  fakeModelsClient,
  modelsProjection,
  modelsView,
} from './fakeModels'

afterEach(() => {
  cleanup()
  setModelsClientForTests(null)
})

function renderPage(client: ReturnType<typeof fakeModelsClient>) {
  setModelsClientForTests(client)
  return render(<MemoryRouter><ModelsPage /></MemoryRouter>)
}

describe('Settings → Models', () => {
  it('without consent: quotes the exact terms, records consent bound to their digest, and re-reads', async () => {
    const client = fakeModelsClient(modelsView())
    renderPage(client)
    const card = await screen.findByTestId('consent-card')
    expect(within(card).getByTestId('consent-terms').textContent).toBe(TERMS)
    expect(within(card).getByRole('link', { name: /provider's terms page/i }).getAttribute('href')).toBe('https://opencode.ai/docs/zen')
    expect(card.textContent).toContain('OpenCode Zen')
    // Free models cannot be evaluated or used before consent.
    expect((screen.getByTestId(`evaluate-${FREE}`) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByTestId(`use-${FREE}`) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(/practice tasks, not from your applications or your work/)).toBeTruthy()
    expect(screen.getByTestId('models-status').textContent).toContain('Free models are off')

    await userEvent.click(within(card).getByTestId('consent-accept'))
    await waitFor(() => expect(client.grantConsent).toHaveBeenCalledWith({ destination: 'opencode-free', termsSha256: TERMS_SHA }))
    await waitFor(() => expect(client.getView).toHaveBeenCalledTimes(2))
  })

  it('Not now sends nothing and leaves free models off', async () => {
    const client = fakeModelsClient(modelsView())
    renderPage(client)
    await userEvent.click(await screen.findByTestId('consent-decline'))
    expect(screen.getByTestId('consent-deferred').textContent).toContain('Nothing is sent')
    expect(client.grantConsent).not.toHaveBeenCalled()
  })

  it('refuses to accept terms whose text does not match the recorded digest', async () => {
    expect(globalThis.crypto?.subtle).toBeTruthy()
    const payload = consentedProjection({
      consent: {
        destination: 'opencode-free',
        state: 'not_granted',
        grantedAt: null,
        grantedBy: null,
        grantedTermsSha256: null,
        terms: { provider: 'OpenCode Zen', url: 'https://opencode.ai/docs/zen', text: TERMS, sha256: `sha256:${'0'.repeat(64)}` },
      },
    })
    const client = fakeModelsClient(modelsView(payload))
    renderPage(client)
    await userEvent.click(await screen.findByTestId('consent-accept'))
    expect((await screen.findByRole('alert')).textContent).toContain('does not match the digest')
    expect(client.grantConsent).not.toHaveBeenCalled()
  })

  it('consented without a route: states "none", lets a free model be evaluated or chosen', async () => {
    const payload = consentedProjection({
      routes: [{
        actionClass: 'agent.edit-state', model: null, pinned: false, setBy: null, setAt: null,
        why: null, ageSeconds: null, score: null, usable: null,
        refusal: { code: 'no_measured_route', message: 'no measured free model is available' },
      }],
    })
    const client = fakeModelsClient(modelsView(payload))
    renderPage(client)
    expect(await screen.findByTestId('consent-granted')).toBeTruthy()
    expect(screen.getByTestId('route-model-agent.edit-state').textContent).toContain('None — no measured free model is available')
    expect(screen.getByTestId('route-score-agent.edit-state').textContent).toBe('Not measured')
    await userEvent.click(screen.getByTestId(`use-${FREE}`))
    await waitFor(() => expect(client.setRoute).toHaveBeenCalledWith({ actionClass: 'agent.edit-state', model: FREE, pin: false }))
  })

  it('follows an evaluation with a progress bar until it settles, then re-reads the scores', async () => {
    const client = fakeModelsClient(modelsView(consentedProjection()))
    client.getRun.mockResolvedValueOnce({
      runId: 'run-1', state: 'running', trigger: 'owner', by: 'owner',
      createdAt: '2026-10-21T09:00:00Z', startedAt: null, finishedAt: null, error: null,
      requestedModels: [FREE],
      progress: { completedTasks: 1, totalTasks: 4, currentModel: FREE, currentTask: 'plain-typo' },
      models: [],
    })
    renderPage(client)
    await userEvent.click(await screen.findByTestId(`evaluate-${FREE}`))
    expect(client.evaluate).toHaveBeenCalledWith([FREE])
    const progress = await screen.findByRole('progressbar', { name: 'Practice tasks done' })
    expect(progress.getAttribute('aria-valuenow')).toBe('1')
    expect(screen.getByText('1 of 4 practice tasks done')).toBeTruthy()
    // Evaluate stays disabled while a run is in flight.
    expect((screen.getByTestId(`evaluate-${OTHER_FREE}`) as HTMLButtonElement).disabled).toBe(true)
    await waitFor(() => expect(screen.getByTestId('evaluation-progress').getAttribute('data-status')).toBe('completed'), { timeout: 5000 })
    await waitFor(() => expect(client.getView.mock.calls.length).toBeGreaterThanOrEqual(3))
  })

  it('pending proposal: shows the service’s own summary and records the decision', async () => {
    const payload = consentedProjection({
      proposal: {
        id: 'proposal-abc', actionClass: 'agent.edit-state', from: FREE, to: OTHER_FREE,
        reason: 'Passes one more practice task.', why: 'the candidate passed more tasks',
        candidate: { passed: 3, total: 4, medianSeconds: 41, runId: 'run-2', finishedAt: '2026-10-21T10:00:00Z', timeouts: 0 },
        incumbent: { passed: 2, total: 4, medianSeconds: 63, runId: 'run-1', finishedAt: '2026-10-21T09:00:00Z', timeouts: 0 },
        suiteDigest: 'sha256:suite', createdAt: '2026-10-21T10:05:00Z', status: 'pending',
        summary: `Switch to ${OTHER_FREE}: 3/4 vs 2/4, 41 s vs 63 s`,
      },
    })
    const client = fakeModelsClient(modelsView(payload))
    renderPage(client)
    expect((await screen.findByTestId('route-proposal-sentence-agent.edit-state')).textContent).toBe(`Switch to ${OTHER_FREE}: 3/4 vs 2/4, 41 s vs 63 s`)
    expect(screen.getByTestId('route-score-agent.edit-state').textContent).toBe('2/4 · median 63 s')
    await userEvent.click(screen.getByTestId('route-proposal-switch-agent.edit-state'))
    await waitFor(() => expect(client.decideProposal).toHaveBeenCalledWith('proposal-abc', 'switch'))
  })

  it('first evaluation: shows the agent AND the chat proposal, each decided on its own', async () => {
    const make = (id: string, actionClass: string) => ({
      id, actionClass, from: null, to: FREE, reason: 'no_incumbent', why: 'no route yet; best measured free model',
      candidate: { passed: 4, total: 4, medianSeconds: 17, runId: 'run-1', finishedAt: '2026-10-22T05:00:00Z', timeouts: 0 },
      incumbent: null, suiteDigest: 'sha256:suite', createdAt: '2026-10-22T05:00:00Z', status: 'pending',
    })
    const payload = consentedProjection({
      proposal: make('proposal-chat', 'chat'),
      proposals: [make('proposal-agent', 'agent.edit-state'), make('proposal-chat', 'chat')],
    })
    const client = fakeModelsClient(modelsView(payload))
    renderPage(client)
    await screen.findByTestId('route-proposal-agent.edit-state')
    expect(screen.getByTestId('route-proposal-chat')).toBeTruthy()
    await userEvent.click(screen.getByTestId('route-proposal-switch-chat'))
    await waitFor(() => expect(client.decideProposal).toHaveBeenCalledWith('proposal-chat', 'switch'))
  })

  it('lease on: shows the expiry, pins and turns automatic updates off through the service', async () => {
    const payload = consentedProjection({
      lease: {
        enabled: true, state: 'active', grantedAt: '2026-10-21T08:00:00Z', expiresAt: '2999-11-20T08:00:00Z',
        maxSuiteRunsPerDay: 1, runsToday: 0, maxDays: 30, defaultDays: 30,
      },
    })
    const client = fakeModelsClient(modelsView(payload))
    renderPage(client)
    const lease = await screen.findByTestId('lease-switch')
    expect(lease.getAttribute('aria-checked')).toBe('true')
    expect(screen.getByTestId('lease-state').textContent).toContain('On until')
    await userEvent.click(lease)
    await waitFor(() => expect(client.setLease).toHaveBeenCalledWith({ enabled: false, days: 30 }))
    await userEvent.click(screen.getByTestId('route-pin-agent.edit-state'))
    await waitFor(() => expect(client.setRoute).toHaveBeenCalledWith({ actionClass: 'agent.edit-state', model: FREE, pin: true }))
  })

  it('shows a refused change as the service said it, never as done', async () => {
    const client = fakeModelsClient(modelsView(consentedProjection()))
    client.setLease.mockRejectedValue(new ClientError('http', 'Only the operator can grant automatic updates.', { status: 403 }))
    renderPage(client)
    await userEvent.click(await screen.findByTestId('lease-switch'))
    expect((await screen.findByRole('alert')).textContent).toContain('Only the operator can grant automatic updates.')
    expect(screen.getByTestId('lease-switch').getAttribute('aria-checked')).toBe('false')
  })

  it('a failed first load is an explicit error, never a default ready', async () => {
    const client = fakeModelsClient(() => Promise.reject(new ClientError('network', 'Could not reach the local StatePort service')))
    renderPage(client)
    expect(await screen.findByText('Model routes could not be loaded')).toBeTruthy()
    expect(screen.getByText(/agent actions stay off/)).toBeTruthy()
    expect(screen.queryByTestId('routes')).toBeNull()
  })

  it('an empty catalogue says so instead of pretending a model exists', async () => {
    const payload = modelsProjection({
      catalogue: {
        observedAt: null, observations: 0, harness: null, lastError: null,
        availabilityWindowSeconds: 604800, cache: null, models: [],
      },
    })
    const client = fakeModelsClient(modelsView(payload))
    renderPage(client)
    expect(await screen.findByTestId('catalogue-empty')).toBeTruthy()
    expect(screen.getByTestId('history-empty').textContent).toContain('Nothing has been recorded yet')
  })
})
