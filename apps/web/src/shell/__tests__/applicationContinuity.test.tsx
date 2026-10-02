import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'

import { ClientError, getClient, resetClientForTests } from '@/client'
import type { ApplicationInstance } from '@/client'
import { buildSeed } from '@/client/mock/seed'
import { useWorkspaceStore } from '@/state'
import { AppContextShell } from '../AppContextShell'
import { invalidateInstanceCache } from '../data'

const instance = buildSeed().instances.find((row) => row.id === 'ins_cto_pilot')!
const prior = { lastInstanceId: 'ins_study_alpha', lastView: 'runs', lastWorkbenchTool: null }

function Navigation() {
  const navigate = useNavigate()
  return <button onClick={() => void navigate(`/app/${instance.id}/conversation`)}>Open valid application</button>
}

function mount(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Navigation />
      <Routes>
        <Route path="/app/:instanceId/*" element={<AppContextShell><div>Loaded application</div></AppContextShell>} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  resetClientForTests()
  invalidateInstanceCache()
  useWorkspaceStore.setState(prior)
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  invalidateInstanceCache()
  resetClientForTests()
})

it.each([
  ['missing', new ClientError('http', 'Application missing', { status: 404 })],
  ['failed', new Error('Service unavailable')],
])('%s deep link preserves prior continuity until a valid application loads', async (_kind, error) => {
  const client = getClient()
  vi.spyOn(client.applications, 'get').mockImplementation(async (id) => {
    if (id !== instance.id) throw error
    return instance
  })
  const touch = vi.spyOn(client.applications, 'touchOpened').mockResolvedValue(undefined)
  mount('/app/ins_missing/settings')
  expect(await screen.findByTestId('error-state')).toBeTruthy()
  expect(useWorkspaceStore.getState()).toMatchObject(prior)
  expect(touch).not.toHaveBeenCalled()

  fireEvent.click(screen.getByRole('button', { name: 'Open valid application' }))
  expect(await screen.findByText('Loaded application')).toBeTruthy()
  await waitFor(() => expect(touch).toHaveBeenCalledWith(instance.id))
  expect(touch).toHaveBeenCalledTimes(1)
  expect(useWorkspaceStore.getState()).toMatchObject({ lastInstanceId: instance.id, lastView: 'conversation' })
})

it('ignores a late successful load after navigating to another application', async () => {
  let resolveOld!: (value: ApplicationInstance) => void
  const pending = new Promise<ApplicationInstance>((resolve) => { resolveOld = resolve })
  const client = getClient()
  vi.spyOn(client.applications, 'get').mockImplementation(async (id) => id === instance.id ? instance : pending)
  const touch = vi.spyOn(client.applications, 'touchOpened').mockResolvedValue(undefined)
  mount('/app/ins_old/settings')
  expect(screen.getByTestId('app-loading')).toBeTruthy()
  expect(useWorkspaceStore.getState()).toMatchObject(prior)
  expect(touch).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Open valid application' }))
  expect(await screen.findByText('Loaded application')).toBeTruthy()
  await act(async () => resolveOld({ ...instance, id: 'ins_old' }))
  expect(useWorkspaceStore.getState()).toMatchObject({ lastInstanceId: instance.id, lastView: 'conversation' })
  expect(touch).toHaveBeenCalledTimes(1)
  expect(touch).toHaveBeenCalledWith(instance.id)
})
