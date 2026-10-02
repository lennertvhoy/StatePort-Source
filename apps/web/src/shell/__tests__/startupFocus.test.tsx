import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom'
import { getClient, resetClientForTests, resetMockState } from '@/client'
import type { GlobalSettings } from '@/client'
import { StartupFocusContext, useSavedNavigationSettings, useStartupFocus } from '../data'
function Tool() {
  useStartupFocus(useLocation().pathname === '/app/one/workbench/files')
  return null
}
function Frame() {
  const session = useSavedNavigationSettings()
  const location = useLocation()
  const navigate = useNavigate()
  return <StartupFocusContext.Provider value={session}>
    <output data-testid="route">{location.pathname}{location.search}{location.hash}</output>
    <button onClick={() => void navigate('/app/one/workbench/files?keep=yes#selection')}>Files</button>
    <button onClick={() => void navigate('/applications')}>Leave</button>
    <button onClick={() => void navigate('/app/one/workbench/files?focus=0')}>Restore</button>
    <button onClick={() => void navigate(-1)}>Back</button>
    <Tool />
  </StartupFocusContext.Provider>
}
function mount(path = '/applications') {
  render(<StrictMode><MemoryRouter initialEntries={[path]}><Frame /></MemoryRouter></StrictMode>)
}
const route = () => screen.getByTestId('route').textContent
beforeEach(() => { resetClientForTests(); resetMockState() })
afterEach(() => { cleanup(); vi.restoreAllMocks(); resetClientForTests() })
async function preference(enabled: boolean, delayed = false) {
  const settings = await getClient().globalSettings.get()
  settings.general.startInFocusMode = enabled
  let resolve!: (value: GlobalSettings) => void
  const pending = new Promise<GlobalSettings>((done) => { resolve = done })
  const get = vi.spyOn(getClient().globalSettings, 'get').mockReturnValue(delayed ? pending : Promise.resolve(settings))
  return { get, finish: async () => { await act(async () => resolve(settings)) } }
}
it('focuses first later eligible tool once, preserving route/query/hash and sharing one startup read under StrictMode', async () => {
  const saved = await preference(true)
  mount()
  await act(async () => {})
  expect(route()).toBe('/applications')
  fireEvent.click(screen.getByText('Files'))
  await waitFor(() => expect(route()).toBe('/app/one/workbench/files?keep=yes&focus=1#selection'))
  fireEvent.click(screen.getByText('Restore')); fireEvent.click(screen.getByText('Leave')); fireEvent.click(screen.getByText('Files'))
  await act(async () => {})
  expect(route()).toBe('/app/one/workbench/files?keep=yes#selection')
  expect(saved.get).toHaveBeenCalledTimes(1)
})
it.each(['0', '1'])('preserves explicit focus=%s and consumes preference', async (focus) => {
  await preference(true)
  mount(`/app/one/workbench/files?focus=${focus}&keep=yes`)
  await act(async () => {})
  expect(route()).toBe(`/app/one/workbench/files?focus=${focus}&keep=yes`)
  fireEvent.click(screen.getByText('Leave')); fireEvent.click(screen.getByText('Files'))
  await act(async () => {})
  expect(route()).toBe('/app/one/workbench/files?keep=yes#selection')
})
it.each(['Leave', 'Restore'])('does not override %s with late response or retry later', async (action) => {
  const saved = await preference(true, true)
  mount('/app/one/workbench/files')
  fireEvent.click(screen.getByText(action))
  const before = route()
  await saved.finish()
  expect(route()).toBe(before)
  fireEvent.click(screen.getByText('Leave')); fireEvent.click(screen.getByText('Files'))
  await act(async () => {})
  expect(route()).toBe('/app/one/workbench/files?keep=yes#selection')
  expect(saved.get).toHaveBeenCalledTimes(1)
})
it('leaves false preference unchanged', async () => {
  await preference(false); mount('/app/one/workbench/files')
  await act(async () => {})
  expect(route()).toBe('/app/one/workbench/files')
})
it('does not consume before eligibility', async () => {
  await preference(true); mount('/app/denied/workbench/files')
  await act(async () => {})
  expect(route()).toBe('/app/denied/workbench/files')
  fireEvent.click(screen.getByText('Files'))
  await waitFor(() => expect(route()).toContain('focus=1'))
})
it('keeps route when settings unavailable', async () => {
  vi.spyOn(getClient().globalSettings, 'get').mockRejectedValue(new Error('offline'))
  mount('/app/one/workbench/files')
  await act(async () => {})
  expect(route()).toBe('/app/one/workbench/files')
})

it('does not retry a cancelled entry when Back restores its original history key', async () => {
  const saved = await preference(true, true)
  mount('/app/one/workbench/files')
  fireEvent.click(screen.getByText('Leave'))
  await act(async () => {})
  fireEvent.click(screen.getByText('Back'))
  await saved.finish()
  expect(route()).toBe('/app/one/workbench/files')
})
