import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { getClient, resetClientForTests, resetMockState } from '@/client'
import type { ApplicationInstance, GlobalSettings } from '@/client'
import { buildSeed } from '@/client/mock/seed'
import { useWorkspaceStore } from '@/state'
import { StartupRoute } from '../StartupRoute'
import { useSavedNavigationSettings } from '../data'

const instance = buildSeed().instances.find((row) => row.id === 'ins_cto_pilot')!
function Frame() {
  useSavedNavigationSettings()
  const location = useLocation()
  const navigate = useNavigate()
  return <><output data-testid="route">{location.pathname}</output><button onClick={() => void navigate('/settings')}>Leave startup</button>
    <Routes><Route path="/" element={<StartupRoute />} /><Route path="*" element={<div>Destination</div>} /></Routes></>
}
function mount(path = '/') { return render(<MemoryRouter initialEntries={[path]}><Frame /></MemoryRouter>) }
async function settings(
  reopen: boolean,
  landing: 'applications' | 'last_workspace',
  preferences: { reopenView?: boolean; restoreTool?: boolean } = {},
) {
  const client = getClient()
  const value = await client.globalSettings.get()
  value.general.reopenLastApplication = reopen
  value.general.defaultLandingPage = landing
  value.general.reopenLastApplicationView = preferences.reopenView ?? true
  value.navigation.restoreLastTool = preferences.restoreTool ?? true
  return { value, get: vi.spyOn(client.globalSettings, 'get').mockResolvedValue(value) }
}
beforeEach(() => {
  resetClientForTests(); resetMockState()
  useWorkspaceStore.setState({ lastInstanceId: instance.id, lastView: 'workbench', lastWorkbenchTool: 'files' })
})
afterEach(() => { cleanup(); vi.restoreAllMocks(); resetClientForTests() })

it.each([
  [true, 'applications', `/app/${instance.id}/workbench/files`],
  [true, 'last_workspace', `/app/${instance.id}/workbench/files`],
  [false, 'applications', '/applications'],
  [false, 'last_workspace', `/app/${instance.id}/workbench/files`],
] as const)('reopen=%s and landing=%s resolves to %s', async (reopen, landing, expected) => {
  const saved = await settings(reopen, landing)
  const get = vi.spyOn(getClient().applications, 'get').mockResolvedValue(instance)
  mount()
  await waitFor(() => expect(screen.getByTestId('route').textContent).toBe(expected))
  expect(saved.get).toHaveBeenCalledTimes(1) // shared with shell bootstrap
  expect(get).toHaveBeenCalledTimes(reopen || landing === 'last_workspace' ? 1 : 0)
})

it.each([
  [true, 'applications', true, true, `/app/${instance.id}/workbench/files`],
  [true, 'applications', false, true, `/app/${instance.id}`],
  [false, 'last_workspace', true, true, `/app/${instance.id}/workbench/files`],
  [false, 'last_workspace', false, true, `/app/${instance.id}`],
  [false, 'last_workspace', true, false, `/app/${instance.id}/workbench`],
  [true, 'applications', true, false, `/app/${instance.id}/workbench`],
] as const)('reopen=%s landing=%s reopenView=%s restoreTool=%s resolves to %s', async (reopen, landing, reopenView, restoreTool, expected) => {
  await settings(reopen, landing, { reopenView, restoreTool })
  vi.spyOn(getClient().applications, 'get').mockResolvedValue(instance)
  mount()
  await waitFor(() => expect(screen.getByTestId('route').textContent).toBe(expected))
})

it.each([null, 'deleted', '../settings', 'a/b', 'a?x=1', '%2Fsettings'])('recovers absent/invalid remembered id %s without changing continuity', async (id) => {
  await settings(true, 'last_workspace')
  useWorkspaceStore.setState({ lastInstanceId: id })
  const get = vi.spyOn(getClient().applications, 'get').mockRejectedValue(new Error('missing'))
  const touch = vi.spyOn(getClient().applications, 'touchOpened')
  mount()
  await waitFor(() => expect(screen.getByTestId('route').textContent).toBe('/applications'))
  expect(useWorkspaceStore.getState().lastInstanceId).toBe(id)
  expect(touch).not.toHaveBeenCalled()
  expect(get).toHaveBeenCalledTimes(id === 'deleted' ? 1 : 0)
})

it('refuses a returned different application identity', async () => {
  await settings(true, 'applications')
  vi.spyOn(getClient().applications, 'get').mockResolvedValue({ ...instance, id: 'other' })
  mount()
  await waitFor(() => expect(screen.getByTestId('route').textContent).toBe('/applications'))
})

it('keeps an explicit deep link even when reopening is enabled', async () => {
  await settings(true, 'last_workspace')
  const get = vi.spyOn(getClient().applications, 'get')
  mount('/app/explicit/receipts/receipt-id')
  await act(async () => {})
  expect(screen.getByTestId('route').textContent).toBe('/app/explicit/receipts/receipt-id')
  expect(get).not.toHaveBeenCalled()
})

it.each(['settings', 'application'])('ignores late %s after leaving startup', async (stage) => {
  const saved = await settings(true, 'applications')
  let resolve!: (value: GlobalSettings & ApplicationInstance) => void
  const pending = new Promise<GlobalSettings & ApplicationInstance>((done) => { resolve = done })
  if (stage === 'settings') saved.get.mockReturnValue(pending)
  else vi.spyOn(getClient().applications, 'get').mockReturnValue(pending)
  mount()
  if (stage === 'application') await waitFor(() => expect(getClient().applications.get).toHaveBeenCalled())
  fireEvent.click(screen.getByText('Leave startup'))
  await act(async () => resolve({ ...saved.value, ...instance }))
  expect(screen.getByTestId('route').textContent).toBe('/settings')
  expect(useWorkspaceStore.getState().lastView).toBe('workbench')
})

it('falls back to Applications if saved settings cannot be loaded', async () => {
  vi.spyOn(getClient().globalSettings, 'get').mockRejectedValue(new Error('offline'))
  mount()
  await waitFor(() => expect(screen.getByTestId('route').textContent).toBe('/applications'))
})
