/** Settings → Models is reachable from the Settings navigation and from the Applications page. */
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import { resetClientForTests } from '@/client'
import { setModelsClientForTests } from '@/client/modelsClient'
import { providerClient } from '@/client/providerClient'
import SettingsPage from '@/features/settings/SettingsPage'
import { SETTINGS_PAGE_LINKS } from '@/features/settings/model'
import { useSessionStore } from '@/state'

import { ModelStatusLine } from '../ModelStatusLine'
import { fakeModelsClient, modelsView } from './fakeModels'

beforeEach(() => {
  resetClientForTests()
  vi.spyOn(providerClient, 'getStatus').mockResolvedValue({
    configured: false, executableInstalled: true, connected: false, model: null,
    authenticationStatus: 'unverified', requestStatus: 'unverified', telemetryStatus: 'unavailable', detail: '',
  })
  setModelsClientForTests(fakeModelsClient(modelsView()))
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: 'http://localhost' } })
})
afterEach(() => {
  cleanup()
  setModelsClientForTests(null)
})

it('the Applications page AI-model line links to Settings → Models', async () => {
  render(<MemoryRouter><ModelStatusLine /></MemoryRouter>)
  await waitFor(() => expect(screen.getByTestId('model-status-link')).toBeTruthy())
  expect(screen.getByTestId('model-status-link').getAttribute('href')).toBe('/settings/models')
})

it('the Settings navigation opens the Models page', async () => {
  render(
    <MemoryRouter initialEntries={['/settings/general']}>
      <Routes>
        <Route path="/settings/models" element={<p>models page</p>} />
        <Route path="/settings/:group" element={<SettingsPage />} />
      </Routes>
    </MemoryRouter>,
  )
  await userEvent.click(await screen.findByTestId('settings-link-models'))
  expect(await screen.findByText('models page')).toBeTruthy()
})

it('the Settings navigation lists Models', async () => {
  render(
    <MemoryRouter initialEntries={['/settings/general']}>
      <Routes>
        <Route path="/settings/:group" element={<SettingsPage />} />
      </Routes>
    </MemoryRouter>,
  )
  const link = await screen.findByTestId('settings-link-models')
  expect(link.textContent).toBe('Models')
})

it('the Models entry explains itself in plain words', () => {
  const entry = SETTINGS_PAGE_LINKS.find((item) => item.id === 'models')
  expect(entry?.description).toContain('practice scores')
})
