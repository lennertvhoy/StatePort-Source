import { act, cleanup, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests, resetMockState, type GlobalSettings } from '@/client'
import { useWorkspaceStore } from '@/state'

import { useGlobalSettings } from '../useGlobalSettings'

beforeEach(() => {
  resetClientForTests()
  resetMockState()
})

afterEach(() => {
  cleanup()
  resetClientForTests()
})

it('keeps edits made during an in-flight save as a visible unsaved draft', async () => {
  const client = getClient()
  const update = client.globalSettings.update.bind(client.globalSettings)
  let finish!: (settings: GlobalSettings) => void
  const pending = new Promise<GlobalSettings>((resolve) => { finish = resolve })
  const saveRequest = vi.spyOn(client.globalSettings, 'update').mockReturnValueOnce(pending)
  const { result } = renderHook(() => useGlobalSettings())
  await waitFor(() => expect(result.current.loading).toBe(false))
  act(() => result.current.set(['appearance.theme', 'dark']))
  let saving!: Promise<void>
  act(() => { saving = result.current.save() })
  await waitFor(() => expect(result.current.saving).toBe(true))
  act(() => result.current.set(['appearance.theme', 'light']))
  expect(useWorkspaceStore.getState().theme).toBe('light')
  await act(async () => {
    finish(await update(saveRequest.mock.calls[0][0]))
    await saving
  })
  expect(result.current.saved?.appearance.theme).toBe('dark')
  expect(result.current.draft?.appearance.theme).toBe('light')
  expect(result.current.dirty).toBe(true)
  expect(useWorkspaceStore.getState().theme).toBe('light')
  // Only the originally submitted draft was persisted by the completed save.
  expect((await client.globalSettings.get()).appearance.theme).toBe('dark')
  await act(async () => { await result.current.save() })
  expect((await client.globalSettings.get()).appearance.theme).toBe('light')
  expect(result.current.dirty).toBe(false)
})
