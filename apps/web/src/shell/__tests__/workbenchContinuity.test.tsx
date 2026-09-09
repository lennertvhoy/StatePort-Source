import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import App from '@/App'
import { getClient, resetClientForTests, resetMockState } from '@/client'
import { useWorkspaceStore, WORKSPACE_STORAGE_KEY } from '@/state'
import { invalidateInstanceCache } from '../data'

beforeEach(() => {
  resetClientForTests(); resetMockState(); invalidateInstanceCache()
  useWorkspaceStore.setState({ lastInstanceId: null, lastView: null, lastWorkbenchTool: null })
})
afterEach(() => { cleanup(); window.location.hash = ''; vi.restoreAllMocks(); resetClientForTests() })
async function savedLanding() {
  await getClient().globalSettings.update({ general: {
    defaultLandingPage: 'last_workspace', reopenLastApplication: false, startInFocusMode: false,
  } })
}
function mount(path: string) {
  window.location.hash = `#${path}`
  return render(<App />)
}

it.each(['files', 'terminal'] as const)('actually visiting %s persists its tool and bare-root startup resumes it', async (tool) => {
  await savedLanding()
  const client = getClient()
  const touch = vi.spyOn(client.applications, 'touchOpened')
  const first = mount(`/app/ins_cto_pilot/workbench/${tool}`)
  await screen.findByTestId(tool === 'files' ? 'files-stub' : 'terminal-stub')
  await waitFor(() => expect(useWorkspaceStore.getState()).toMatchObject({
    lastInstanceId: 'ins_cto_pilot', lastView: 'workbench', lastWorkbenchTool: tool,
  }))
  expect(JSON.parse(localStorage.getItem(WORKSPACE_STORAGE_KEY)!).state.lastWorkbenchTool).toBe(tool)
  expect(touch).toHaveBeenCalledTimes(1) // no extra timestamp request from tool recording
  first.unmount()
  await act(async () => { await useWorkspaceStore.persist.rehydrate() })
  mount('/')
  await waitFor(() => expect(window.location.hash).toBe(`#/app/ins_cto_pilot/workbench/${tool}`))
})

it('switching actual tools replaces the global remembered tool without an extra opened request', async () => {
  const touch = vi.spyOn(getClient().applications, 'touchOpened')
  mount('/app/ins_cto_pilot/workbench/files')
  await waitFor(() => expect(useWorkspaceStore.getState().lastWorkbenchTool).toBe('files'))
  const before = touch.mock.calls.length
  await act(async () => { window.location.hash = '#/app/ins_cto_pilot/workbench/terminal' })
  await waitFor(() => expect(useWorkspaceStore.getState().lastWorkbenchTool).toBe('terminal'))
  expect(touch).toHaveBeenCalledTimes(before)
})

it('denied deployment entry is never recorded and startup resumes the actual permitted fallback', async () => {
  await savedLanding()
  const recorded: unknown[] = []
  const unsubscribe = useWorkspaceStore.subscribe((state) => recorded.push(state.lastWorkbenchTool))
  const first = mount('/app/ins_cto_pilot/workbench/deployments')
  await waitFor(() => expect(window.location.hash).toBe('#/app/ins_cto_pilot/workbench'))
  await waitFor(() => expect(useWorkspaceStore.getState().lastWorkbenchTool).toBe('overview'))
  expect(recorded).not.toContain('deployments')
  unsubscribe(); first.unmount()
  mount('/')
  await waitFor(() => expect(window.location.hash).toBe('#/app/ins_cto_pilot/workbench'))
})

it('deleted application link preserves the last successfully visited tool', async () => {
  const first = mount('/app/ins_cto_pilot/workbench/files')
  await waitFor(() => expect(useWorkspaceStore.getState().lastWorkbenchTool).toBe('files'))
  first.unmount()
  mount('/app/missing/workbench/terminal')
  await screen.findByTestId('error-state')
  expect(useWorkspaceStore.getState()).toMatchObject({ lastInstanceId: 'ins_cto_pilot', lastWorkbenchTool: 'files' })
})
