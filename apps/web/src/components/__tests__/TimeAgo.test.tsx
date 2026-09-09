import { act, cleanup, fireEvent, render, renderHook, screen } from '@testing-library/react'
import { format } from 'date-fns'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { getClient, resetClientForTests } from '@/client'
import type { GlobalSettings } from '@/client'
import { applySavedSettingsToWorkspace } from '@/features/settings/model'
import { useSavedNavigationSettings } from '@/shell/data'
import { useWorkspaceStore } from '@/state'
import { TimeAgo } from '../TimeAgo'
const timestamp = '2026-09-06T01:00:00.000Z'
beforeEach(() => {
  resetClientForTests()
  localStorage.clear()
  useWorkspaceStore.setState(useWorkspaceStore.getInitialState(), true)
})
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks() })
it('renders saved modes while preserving canonical datetime and absolute tooltip', () => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-09-06T01:02:00Z'))
  const view = render(<TimeAgo date={timestamp} />)
  const time = view.container.querySelector('time')!
  const absolute = format(new Date(timestamp), 'PPpp')
  expect(time.textContent).toBe('2 minutes ago')
  expect(time.classList.contains('whitespace-nowrap')).toBe(true)
  expect(time.dateTime).toBe(timestamp)
  fireEvent.focus(time)
  expect(screen.getByRole('tooltip').textContent).toBe(absolute)
  fireEvent.blur(time)
  act(() => useWorkspaceStore.getState().setDateTimeFormat('absolute'))
  expect(time.textContent).toBe(absolute)
  expect(time.classList.contains('whitespace-normal')).toBe(true)
  expect(time.classList.contains('whitespace-nowrap')).toBe(false)
  act(() => useWorkspaceStore.getState().setDateTimeFormat('both'))
  expect(time.textContent).toBe(`2 minutes ago · ${absolute}`)
  expect(time.classList.contains('whitespace-normal')).toBe(true)
  expect(time.dateTime).toBe(timestamp)
})
it('shares one minute timer and removes it with the last relative subscriber', () => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-09-06T01:02:00Z'))
  const interval = vi.spyOn(window, 'setInterval')
  const clear = vi.spyOn(window, 'clearInterval')
  const first = render(<TimeAgo date={timestamp} />)
  const second = render(<TimeAgo date={timestamp} />)
  expect(interval).toHaveBeenCalledTimes(1)
  act(() => vi.advanceTimersByTime(60_000))
  expect(first.container.querySelector('time')?.textContent).toBe('3 minutes ago')
  expect(second.container.querySelector('time')?.textContent).toBe('3 minutes ago')
  first.unmount()
  expect(clear).not.toHaveBeenCalled()
  second.unmount()
  expect(clear).toHaveBeenCalledTimes(1)
  act(() => useWorkspaceStore.getState().setDateTimeFormat('absolute'))
  const absolute = render(<TimeAgo date={timestamp} />)
  expect(interval).toHaveBeenCalledTimes(1)
  act(() => useWorkspaceStore.getState().setDateTimeFormat('both'))
  expect(interval).toHaveBeenCalledTimes(2)
  act(() => useWorkspaceStore.getState().setDateTimeFormat('absolute'))
  expect(clear).toHaveBeenCalledTimes(2)
  absolute.unmount()
})
it('mirrors saved settings durably and preserves the mirror on offline bootstrap', async () => {
  const settings = await getClient().globalSettings.update({ general: { dateTimeFormat: 'both' } })
  applySavedSettingsToWorkspace(settings)
  const saved = localStorage.getItem('stateport.workspace.v1')!
  expect(JSON.parse(saved).state.dateTimeFormat).toBe('both')
  expect(JSON.parse(saved).state.dateTimeFormatGeneration).toBeUndefined()
  useWorkspaceStore.setState({ dateTimeFormat: 'relative', dateTimeFormatGeneration: 0 })
  localStorage.setItem('stateport.workspace.v1', saved)
  await useWorkspaceStore.persist.rehydrate()
  expect(useWorkspaceStore.getState().dateTimeFormat).toBe('both')
  vi.spyOn(getClient().globalSettings, 'get').mockRejectedValue(new Error('Offline'))
  renderHook(() => useSavedNavigationSettings())
  await act(async () => {})
  expect(useWorkspaceStore.getState().dateTimeFormat).toBe('both')
})
it.each(['relative', 'absolute'] as const)('a newer %s save wins over late initial GET, including same-value saves', async (mode) => {
  const settings = await getClient().globalSettings.get()
  settings.general.dateTimeFormat = 'both'
  let finish!: (value: GlobalSettings) => void
  vi.spyOn(getClient().globalSettings, 'get').mockReturnValue(new Promise((resolve) => { finish = resolve }))
  renderHook(() => useSavedNavigationSettings())
  act(() => applySavedSettingsToWorkspace({ ...settings, general: { ...settings.general, dateTimeFormat: mode } }))
  expect(useWorkspaceStore.getState().dateTimeFormatGeneration).toBe(1)
  await act(async () => finish(settings))
  expect(useWorkspaceStore.getState().dateTimeFormat).toBe(mode)
})
it('loads saved mode once at bootstrap without per-timestamp requests', async () => {
  const settings = await getClient().globalSettings.get()
  settings.general.dateTimeFormat = 'absolute'
  const get = vi.spyOn(getClient().globalSettings, 'get').mockResolvedValue(settings)
  function Bootstrap() { useSavedNavigationSettings(); return <><TimeAgo date={timestamp} /><TimeAgo date={timestamp} /></> }
  const view = render(<Bootstrap />)
  await act(async () => {})
  expect(get).toHaveBeenCalledTimes(1)
  expect([...view.container.querySelectorAll('time')].map((time) => time.textContent)).toEqual([
    format(new Date(timestamp), 'PPpp'), format(new Date(timestamp), 'PPpp'),
  ])
})
