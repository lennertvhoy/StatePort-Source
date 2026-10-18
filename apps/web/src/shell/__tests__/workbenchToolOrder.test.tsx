import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import App from '@/App'
import { ClientError, getClient, resetClientForTests, resetMockState } from '@/client'
import type { GlobalSettings } from '@/client'
import { DEFAULT_WORKBENCH_TOOL_ORDER, normalizeWorkbenchToolOrder, useWorkspaceStore } from '@/state'
import { NavigationGroup } from '@/features/settings/GlobalGroups'
import { useGlobalSettings } from '@/features/settings/useGlobalSettings'
import { applySavedSettingsToWorkspace } from '@/features/settings/model'
import { invalidateInstanceCache } from '../data'
import { getShortcutAction } from '../shortcutRegistry'
import { useCommandStore } from '../commands'

function SettingsHarness() {
  const controller = useGlobalSettings()
  if (!controller.draft) return null
  return <>
    <NavigationGroup settings={controller.draft} set={controller.set} />
    <button onClick={() => void controller.save()}>Save order</button>
    <button onClick={controller.discard}>Discard order</button>
    <output data-testid="save-error">{controller.saveError}</output>
    <output data-testid="dirty">{String(controller.dirty)}</output>
  </>
}
const expectedDefault = ['Overview', 'Files', 'Terminal', 'Orchestration', 'Receipts']
const tabs = () => within(screen.getByTestId('tool-header')).getAllByRole('link').map((el) => el.textContent)
async function mount(extra = false) {
  window.location.hash = '#/app/ins_cto_pilot/workbench'
  const result = render(<><App />{extra && <SettingsHarness />}</>)
  await screen.findByTestId('tool-header')
  return result
}
beforeEach(() => {
  resetClientForTests(); resetMockState(); invalidateInstanceCache()
  useWorkspaceStore.setState({ workbenchToolOrder: [...DEFAULT_WORKBENCH_TOOL_ORDER], workbenchToolOrderGeneration: 0 })
})
afterEach(() => { cleanup(); window.location.hash = ''; vi.restoreAllMocks(); resetClientForTests() })

it('normalizes untrusted shape without hiding, inventing or duplicating known tools', () => {
  expect(normalizeWorkbenchToolOrder(['receipts', 'receipts', 'foreign', null, 'files'])).toEqual([
    'receipts', 'files', 'overview', 'terminal', 'deployments', 'orchestration',
  ])
  expect(normalizeWorkbenchToolOrder(null)).toEqual(DEFAULT_WORKBENCH_TOOL_ORDER)
  expect(normalizeWorkbenchToolOrder([])).toEqual(DEFAULT_WORKBENCH_TOOL_ORDER)
})

it('loads saved order into actual tabs, numbered actions and palette while capability-denied tools stay absent', async () => {
  await getClient().globalSettings.update({ navigation: { workbenchToolOrder: ['deployments', 'receipts', 'files'] } })
  await mount()
  await waitFor(() => expect(tabs()).toEqual(['Receipts', 'Files', 'Overview', 'Terminal', 'Orchestration']))
  expect(useCommandStore.getState().commands['workbench.tool.receipts']?.shortcut).toBe('mod+1')
  expect(Boolean(useCommandStore.getState().commands['workbench.tool.deployments'])).toBe(false)
  act(() => getShortcutAction('workbench.tool_1')!.handler())
  await waitFor(() => expect(window.location.hash).toBe('#/app/ins_cto_pilot/workbench/receipts'))
})

it('draft/discard do not reorder tabs; successful Save takes effect immediately and survives remount', async () => {
  const result = await mount(true)
  await screen.findByTestId('settings-group-navigation')
  fireEvent.click(screen.getByRole('button', { name: 'Move Files up' }))
  expect(tabs()).toEqual(expectedDefault)
  fireEvent.click(screen.getByText('Discard order'))
  expect(tabs()).toEqual(expectedDefault)
  fireEvent.click(screen.getByRole('button', { name: 'Move Files up' }))
  fireEvent.click(screen.getByText('Save order'))
  await waitFor(() => expect(tabs()).toEqual(['Files', 'Overview', 'Terminal', 'Orchestration', 'Receipts']))
  expect((await getClient().globalSettings.get()).navigation.workbenchToolOrder[0]).toBe('files')
  result.unmount()
  useWorkspaceStore.setState({ workbenchToolOrder: [...DEFAULT_WORKBENCH_TOOL_ORDER], workbenchToolOrderGeneration: 0 })
  await mount()
  await waitFor(() => expect(tabs()[0]).toBe('Files'))
})

it('a refused Save preserves the visible order and saved preference', async () => {
  await mount(true)
  await screen.findByTestId('settings-group-navigation')
  vi.spyOn(getClient().globalSettings, 'update').mockRejectedValue(new ClientError('http', 'Read-only settings', { status: 403 }))
  fireEvent.click(screen.getByRole('button', { name: 'Move Files up' }))
  fireEvent.click(screen.getByText('Save order'))
  await waitFor(() => expect(screen.getByTestId('save-error').textContent).toBe('Read-only settings'))
  expect(tabs()).toEqual(expectedDefault)
  expect((await getClient().globalSettings.get()).navigation.workbenchToolOrder).toEqual(DEFAULT_WORKBENCH_TOOL_ORDER)
})

it('late bootstrap cannot overwrite a more recent save, including a same-value save', async () => {
  const saved = await getClient().globalSettings.get()
  const old = structuredClone(saved)
  old.navigation.workbenchToolOrder = ['receipts']
  let resolve!: (value: GlobalSettings) => void
  vi.spyOn(getClient().globalSettings, 'get').mockReturnValue(new Promise((done) => { resolve = done }))
  await mount()
  act(() => applySavedSettingsToWorkspace(saved))
  await act(async () => resolve(old))
  expect(tabs()).toEqual(expectedDefault)
})

it('failed initial settings load retains default order without changing the route', async () => {
  vi.spyOn(getClient().globalSettings, 'get').mockRejectedValue(new Error('offline'))
  await mount()
  expect(tabs()).toEqual(expectedDefault)
  expect(window.location.hash).toBe('#/app/ins_cto_pilot/workbench')
})

it('mobile tool selector follows the same saved filtered order', async () => {
  const original = window.matchMedia.bind(window)
  vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({
    ...original(query), matches: query === '(max-width: 767px)',
  }))
  await getClient().globalSettings.update({ navigation: { workbenchToolOrder: ['receipts', 'deployments', 'files'] } })
  window.location.hash = '#/app/ins_cto_pilot/workbench'
  render(<App />)
  const selector = await screen.findByTestId('tool-selector')
  fireEvent.pointerDown(selector, { button: 0, ctrlKey: false })
  await waitFor(() => expect(screen.getAllByRole('menuitem').map((item) => item.textContent)).toEqual([
    'Receipts', 'Files', 'Overview', 'Terminal', 'Orchestration',
  ]))
})

it('numbered actions invoked from focus mode use the same saved ordering and existing tool route', async () => {
  await getClient().globalSettings.update({ navigation: { workbenchToolOrder: ['receipts', 'files'] } })
  window.location.hash = '#/app/ins_cto_pilot/workbench?focus=1'
  render(<App />)
  await screen.findByTestId('workbench-focus')
  await waitFor(() => expect(useCommandStore.getState().commands['workbench.tool.receipts']?.shortcut).toBe('mod+1'))
  act(() => getShortcutAction('workbench.tool_1')!.handler())
  await waitFor(() => expect(window.location.hash).toBe('#/app/ins_cto_pilot/workbench/receipts'))
  // Existing goTool routing drops query presentation, including focus, on tool changes.
  expect(screen.getByTestId('workbench-shell')).toBeTruthy()
})
