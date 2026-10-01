import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests, resetMockState } from '@/client'
import { AppContextShell } from '@/shell/AppContextShell'

import SettingsPage from '../SettingsPage'

beforeEach(() => { resetClientForTests(); resetMockState() })
afterEach(cleanup)

function SwitchApplication() {
  const navigate = useNavigate()
  return <button onClick={() => void navigate('/app/ins_study_alpha/settings?group=conversation')}>Switch application</button>
}

it('does not apply a previous application save response to the newly opened application draft', async () => {
  const client = getClient()
  await client.appSettings.update('ins_study_alpha', { conversation: { defaultContext: ['receipt'] } })
  const original = client.appSettings.update.bind(client.appSettings)
  let release!: () => void
  const pending = new Promise<void>((resolve) => { release = resolve })
  let saved!: Promise<unknown>
  vi.spyOn(client.appSettings, 'update').mockImplementationOnce((id, patch) => {
    saved = original(id, patch).then(async (result) => { await pending; return result })
    return saved as ReturnType<typeof original>
  })
  render(<MemoryRouter initialEntries={['/app/ins_cto_pilot/settings?group=conversation']}>
    <SwitchApplication />
    <Routes><Route path="/app/:instanceId" element={<AppContextShell />}>
      <Route path="settings" element={<SettingsPage />} />
    </Route></Routes>
  </MemoryRouter>)
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Conversation summary' }))
  fireEvent.click(screen.getByTestId('app-settings-save'))
  await waitFor(() => expect(client.appSettings.update).toHaveBeenCalled())
  fireEvent.click(screen.getByRole('button', { name: 'Switch application' }))
  await waitFor(() => expect((screen.getByRole('checkbox', { name: 'Recent receipts' }) as HTMLInputElement).checked).toBe(true))
  await act(async () => { release(); await saved })
  expect((screen.getByRole('checkbox', { name: 'Recent receipts' }) as HTMLInputElement).checked).toBe(true)
  expect((screen.getByRole('checkbox', { name: 'Application' }) as HTMLInputElement).checked).toBe(false)
  expect((await client.appSettings.get('ins_study_alpha')).conversation.defaultContext).toEqual(['receipt'])
})
