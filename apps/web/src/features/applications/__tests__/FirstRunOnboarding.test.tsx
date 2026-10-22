import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { setModelsClientForTests } from '@/client/modelsClient'
import { providerClient, type ProviderStatus } from '@/client/providerClient'
import {
  TERMS_SHA,
  consentedProjection,
  fakeModelsClient,
  modelsView,
} from '@/features/models/__tests__/fakeModels'

import { FirstRunOnboarding } from '../components/FirstRunOnboarding'

const NO_PROVIDER: ProviderStatus = {
  configured: false, executableInstalled: true, connected: false, model: null, providerId: 'opencode',
  authenticationStatus: 'unverified', requestStatus: 'unverified', telemetryStatus: 'unavailable', detail: '',
}

function LocationProbe() {
  return <output data-testid="path">{useLocation().pathname}</output>
}

function renderOnboarding(props: Partial<Parameters<typeof FirstRunOnboarding>[0]> = {}) {
  const handlers = { onOpenSample: vi.fn(), onImport: vi.fn(), onBrowse: vi.fn() }
  render(
    <MemoryRouter>
      <LocationProbe />
      <FirstRunOnboarding sampleInstalling={false} readOnly={false} hasApplications={false} firstRunDone={false} {...handlers} {...props} />
    </MemoryRouter>,
  )
  return handlers
}

const step = (name: 'route' | 'app' | 'run') => screen.getByTestId(`onboarding-step-${name}`)

beforeEach(() => {
  vi.spyOn(providerClient, 'getStatus').mockResolvedValue(NO_PROVIDER)
})
afterEach(() => {
  cleanup()
  setModelsClientForTests(null)
})

describe('first-run onboarding', () => {
  it('starts with nothing done and offers both AI routes and the three ways to create an application', async () => {
    setModelsClientForTests(fakeModelsClient(modelsView()))
    const handlers = renderOnboarding()
    expect(screen.getByText('Checking the AI route…')).toBeTruthy()
    await screen.findByTestId('onboarding-free-models')
    expect(step('route').getAttribute('data-done')).toBe('false')
    expect(step('app').getAttribute('data-done')).toBe('false')
    expect(step('run').getAttribute('data-done')).toBe('false')
    expect(within(step('run')).getByText(/After step 2/)).toBeTruthy()

    await userEvent.click(screen.getByRole('button', { name: 'Open the study sample' }))
    await userEvent.click(screen.getByRole('button', { name: 'Import a template' }))
    await userEvent.click(screen.getByRole('button', { name: 'Browse catalog' }))
    expect(handlers.onOpenSample).toHaveBeenCalledTimes(1)
    expect(handlers.onImport).toHaveBeenCalledTimes(1)
    expect(handlers.onBrowse).toHaveBeenCalledTimes(1)
    expect(screen.getByText(/ProjectState, StudyState, or any public Git repository/)).toBeTruthy()

    await userEvent.click(screen.getByTestId('onboarding-own-account'))
    expect(screen.getByTestId('path').textContent).toBe('/settings/provider')
  })

  it('"Use free models" opens the consent card; accepting records consent and marks step 1 done', async () => {
    const grantedWithoutRoute = consentedProjection({
      routes: [{
        actionClass: 'agent.edit-state', model: null, pinned: false, setBy: null, setAt: null,
        why: null, ageSeconds: null, score: null, usable: null,
        refusal: { code: 'no_measured_route', message: 'no measured free model is available' },
      }],
    })
    const client = fakeModelsClient(modelsView())
    client.getView
      .mockResolvedValueOnce(modelsView())
      .mockResolvedValue(modelsView(grantedWithoutRoute))
    setModelsClientForTests(client)
    renderOnboarding()
    await userEvent.click(await screen.findByTestId('onboarding-free-models'))
    const dialog = await screen.findByRole('dialog')
    await userEvent.click(within(dialog).getByTestId('consent-accept'))
    await waitFor(() => expect(client.grantConsent).toHaveBeenCalledWith({ destination: 'opencode-free', termsSha256: TERMS_SHA }))
    await waitFor(() => expect(step('route').getAttribute('data-done')).toBe('true'))
    expect(screen.getByTestId('onboarding-route-state').textContent).toContain('Free models allowed.')
    expect(screen.getByTestId('onboarding-route-state').textContent).toContain('No free model has been measured yet')
  })

  it('counts the free route as done; an own account alone serves chat, not agent actions', async () => {
    setModelsClientForTests(fakeModelsClient(modelsView(consentedProjection())))
    renderOnboarding()
    await waitFor(() => expect(step('route').getAttribute('data-done')).toBe('true'))
    expect(screen.getByTestId('onboarding-route-state').textContent).toBe('Free models allowed.')
    cleanup()

    setModelsClientForTests(fakeModelsClient(modelsView()))
    vi.mocked(providerClient.getStatus).mockResolvedValue({ ...NO_PROVIDER, configured: true, credentialStatus: 'configured', credentialProvider: 'openrouter' })
    renderOnboarding()
    await waitFor(() => expect(screen.getByTestId('onboarding-route-state').textContent).toContain('free models'))
    expect(step('route').getAttribute('data-done')).toBe('false')
    expect(screen.getByTestId('onboarding-own-account').textContent).toBe('For chat: connect your own OpenCode sign-in or API key')
  })

  it('says plainly when the AI route cannot be checked, and marks step 2 done from real inventory', async () => {
    setModelsClientForTests(fakeModelsClient(() => Promise.reject(new Error('offline'))))
    vi.mocked(providerClient.getStatus).mockRejectedValue(new Error('offline'))
    renderOnboarding({ hasApplications: true })
    expect((await screen.findByTestId('onboarding-route-state')).textContent).toContain('could not check')
    expect(step('route').getAttribute('data-done')).toBe('false')
    expect(step('app').getAttribute('data-done')).toBe('true')
    expect(within(step('run')).getByText(/press Run on one of its actions/)).toBeTruthy()
  })

  it('marks step 3 done only when a run exists', async () => {
    setModelsClientForTests(fakeModelsClient(modelsView()))
    renderOnboarding({ hasApplications: true, firstRunDone: true })
    await waitFor(() => expect(step('run').getAttribute('data-done')).toBe('true'))
  })

  it('keeps the sample action disabled while it installs', async () => {
    setModelsClientForTests(fakeModelsClient(modelsView()))
    renderOnboarding({ sampleInstalling: true })
    expect((screen.getByRole('button', { name: 'Preparing the study sample' }) as HTMLButtonElement).disabled).toBe(true)
    await screen.findByTestId('onboarding-free-models')
  })
})
