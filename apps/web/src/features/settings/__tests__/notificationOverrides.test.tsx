/**
 * Notification overrides honesty — the application list for per-application
 * overrides must never render as an empty list when the load failed. An
 * access failure surfaces an honest unavailable state instead.
 */
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { ClientError, getClient, resetClientForTests, resetMockState } from '@/client'

import SettingsPage from '../SettingsPage'

function renderNotifications() {
  return render(
    <MemoryRouter initialEntries={['/settings/notifications']}>
      <Routes>
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/settings/:group" element={<SettingsPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  resetClientForTests()
  resetMockState()
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  resetClientForTests()
})

describe('Notifications settings — application overrides', () => {
  it('shows an honest unavailable state when the application list cannot be loaded', async () => {
    vi.spyOn(getClient().applications, 'list').mockRejectedValue(
      new ClientError('http', 'Forbidden', { status: 403 }),
    )
    renderNotifications()

    expect(await screen.findByTestId('app-overrides-unavailable')).toBeTruthy()
    expect(screen.queryByText('No applications installed — nothing to override yet.')).toBeNull()
  })

  it('lists applications for override when the load succeeds', async () => {
    renderNotifications()

    expect(await screen.findByTestId('settings-group-notifications')).toBeTruthy()
    await waitFor(() => {
      expect(document.querySelector('[data-setting-anchor^="override-"]')).toBeTruthy()
    })
    expect(screen.queryByTestId('app-overrides-unavailable')).toBeNull()
  })
})
