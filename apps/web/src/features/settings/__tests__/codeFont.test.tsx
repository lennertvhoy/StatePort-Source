import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { ClientError, getClient, resetClientForTests, resetMockState } from '@/client'
import { AppearanceGroup, EditorGroup } from '../GlobalGroups'
import { TerminalGroup } from '../GlobalGroups2'
import { useGlobalSettings } from '../useGlobalSettings'

function Harness() {
  const controller = useGlobalSettings()
  if (!controller.draft) return <div>Loading</div>
  return <>
    <AppearanceGroup settings={controller.draft} set={controller.set} />
    <EditorGroup settings={controller.draft} set={controller.set} />
    <TerminalGroup settings={controller.draft} set={controller.set} />
    <button onClick={() => void controller.save()}>Save draft</button>
    <button onClick={controller.discard}>Discard draft</button>
    <output data-testid="dirty">{String(controller.dirty)}</output>
    <output data-testid="save-error">{controller.saveError}</output>
  </>
}
function control(anchor: string) {
  return document.getElementById(`setting-${anchor}`)!.querySelector('select,input')!
}
async function ready() { await screen.findByTestId('settings-group-appearance') }

beforeEach(() => { resetClientForTests(); resetMockState() })
afterEach(() => { cleanup(); vi.restoreAllMocks(); resetClientForTests() })

it('common font edits both consumer settings in the draft, saves together and preserves later overrides', async () => {
  const client = getClient()
  const update = vi.spyOn(client.globalSettings, 'update')
  const mounted = render(<Harness />)
  await ready()
  fireEvent.change(control('code-font'), { target: { value: 'system' } })
  expect((control('editor-font') as HTMLSelectElement).value).toBe('system')
  expect((control('terminal-font') as HTMLInputElement).value).toBe('system')
  expect(update).not.toHaveBeenCalled()
  expect((await client.globalSettings.get()).editor.fontFamily).toBe('JetBrains Mono')
  fireEvent.click(screen.getByText('Save draft'))
  await waitFor(() => expect(screen.getByTestId('dirty').textContent).toBe('false'))
  expect(update).toHaveBeenCalledTimes(1)
  expect(await client.globalSettings.get()).toMatchObject({ appearance: { codeFont: 'system' }, editor: { fontFamily: 'system' }, terminal: { fontFamily: 'system' } })
  mounted.unmount()
  render(<Harness />)
  await ready()
  expect((control('code-font') as HTMLSelectElement).value).toBe('system')
  fireEvent.change(control('editor-font'), { target: { value: 'JetBrains Mono' } })
  fireEvent.change(control('terminal-font'), { target: { value: 'Custom Monospace' } })
  expect((control('code-font') as HTMLSelectElement).value).toBe('system')
  fireEvent.click(screen.getByText('Save draft'))
  await waitFor(() => expect(screen.getByTestId('dirty').textContent).toBe('false'))
  expect(await client.globalSettings.get()).toMatchObject({ appearance: { codeFont: 'system' }, editor: { fontFamily: 'JetBrains Mono' }, terminal: { fontFamily: 'Custom Monospace' } })
})

it('keeps all saved fonts unchanged on permission refusal and discards the coordinated draft', async () => {
  const client = getClient()
  const before = await client.globalSettings.get()
  vi.spyOn(client.globalSettings, 'update').mockRejectedValue(new ClientError('http', 'Read-only settings', { status: 403 }))
  render(<Harness />)
  await ready()
  fireEvent.change(control('code-font'), { target: { value: 'system' } })
  fireEvent.click(screen.getByText('Save draft'))
  await waitFor(() => expect(screen.getByTestId('save-error').textContent).toBe('Read-only settings'))
  expect(screen.getByTestId('dirty').textContent).toBe('true')
  expect(await client.globalSettings.get()).toEqual(before)
  fireEvent.click(screen.getByText('Discard draft'))
  expect((control('code-font') as HTMLSelectElement).value).toBe(before.appearance.codeFont)
  expect((control('editor-font') as HTMLSelectElement).value).toBe(before.editor.fontFamily)
  expect((control('terminal-font') as HTMLInputElement).value).toBe(before.terminal.fontFamily)
})
