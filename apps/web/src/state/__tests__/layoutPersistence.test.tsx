import { act, cleanup, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { getClient, resetClientForTests, resetMockState } from '@/client'
import type { GlobalSettings } from '@/client'
import { buildSeed } from '@/client/mock/seed'
import { applySavedSettingsToWorkspace } from '@/features/settings/model'
import { useSavedNavigationSettings } from '@/shell/data'
import { DEFAULT_LAYOUT, useWorkspaceStore, WORKSPACE_STORAGE_KEY } from '../workspace'

beforeEach(() => {
  resetClientForTests(); resetMockState()
  localStorage.removeItem(WORKSPACE_STORAGE_KEY)
  useWorkspaceStore.setState({ layouts: {}, restoreWorkspaceLayouts: true, layoutPersistenceGeneration: 0 })
})
afterEach(() => { cleanup(); vi.restoreAllMocks(); resetClientForTests() })

async function reloadWorkspace() {
  const saved = localStorage.getItem(WORKSPACE_STORAGE_KEY)!
  useWorkspaceStore.setState({ layouts: {}, restoreWorkspaceLayouts: true })
  localStorage.setItem(WORKSPACE_STORAGE_KEY, saved)
  await useWorkspaceStore.persist.rehydrate()
}

it('saving disabled preserves current layouts but omits them from storage and a reload', async () => {
  const store = useWorkspaceStore.getState()
  store.setLayout('first', { navSize: 420 })
  store.setLayout('second', { bottomCollapsed: true })
  const settings = buildSeed().globalSettings
  settings.general.restoreWorkspaceLayouts = false
  applySavedSettingsToWorkspace(settings)
  store.setLayout('first', { navSize: 480 })
  expect(useWorkspaceStore.getState().getLayout('first').navSize).toBe(480)
  expect(JSON.parse(localStorage.getItem(WORKSPACE_STORAGE_KEY)!).state.layouts).toEqual({})
  await reloadWorkspace()
  expect(useWorkspaceStore.getState().getLayout('first')).toEqual(DEFAULT_LAYOUT)
  expect(useWorkspaceStore.getState().getLayout('second')).toEqual(DEFAULT_LAYOUT)
  expect(useWorkspaceStore.getState().restoreWorkspaceLayouts).toBe(false)
})

it('reenabling saves the current per-application layouts for subsequent reload', async () => {
  const store = useWorkspaceStore.getState()
  store.setRestoreWorkspaceLayouts(false)
  store.setLayout('first', { navSize: 410 })
  store.setLayout('second', { navSize: 390 })
  const settings = buildSeed().globalSettings
  settings.general.restoreWorkspaceLayouts = true
  applySavedSettingsToWorkspace(settings)
  await reloadWorkspace()
  expect(useWorkspaceStore.getState().getLayout('first').navSize).toBe(410)
  expect(useWorkspaceStore.getState().getLayout('second').navSize).toBe(390)
})

it('bootstrap discards untouched saved layouts when the service preference is disabled', async () => {
  useWorkspaceStore.getState().setLayout('first', { navSize: 420 })
  const settings = buildSeed().globalSettings
  settings.general.restoreWorkspaceLayouts = false
  vi.spyOn(getClient().globalSettings, 'get').mockResolvedValue(settings)
  renderHook(() => useSavedNavigationSettings())
  await waitFor(() => expect(useWorkspaceStore.getState().restoreWorkspaceLayouts).toBe(false))
  expect(useWorkspaceStore.getState().layouts).toEqual({})
})

it.each(['save', 'edit'] as const)('late bootstrap does not erase a newer %s', async (action) => {
  let resolve!: (value: GlobalSettings) => void
  vi.spyOn(getClient().globalSettings, 'get').mockReturnValue(new Promise((done) => { resolve = done }))
  renderHook(() => useSavedNavigationSettings())
  act(() => {
    useWorkspaceStore.getState().setLayout('first', { navSize: 490 })
    if (action === 'save') applySavedSettingsToWorkspace(buildSeed().globalSettings)
  })
  const older = buildSeed().globalSettings
  older.general.restoreWorkspaceLayouts = false
  await act(async () => resolve(older))
  expect(useWorkspaceStore.getState().getLayout('first').navSize).toBe(490)
  expect(useWorkspaceStore.getState().restoreWorkspaceLayouts).toBe(action === 'save')
})
