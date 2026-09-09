/**
 * Command registry — useRegisterCommands registers for the component's
 * lifetime and auto-unregisters on unmount (the feature-agent contract).
 */
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests } from '@/client'
import { useSessionStore } from '@/state'
import { CommandPalette } from '../CommandPalette'

import type { ShellCommand } from '../commands'
import { availableCommands, useCommandStore, useRegisterCommands } from '../commands'

const cmd = (id: string, when?: () => boolean): ShellCommand => ({
  id,
  title: `Command ${id}`,
  group: 'Actions',
  run: () => undefined,
  when,
})

function Probe({ commands }: { commands: ShellCommand[] }) {
  useRegisterCommands(commands)
  return null
}

afterEach(() => {
  vi.restoreAllMocks()
  cleanup()
  useCommandStore.setState({ commands: {}, paletteOpen: false, shortcutsOpen: false })
})

describe('command registry', () => {
  it('registers commands while mounted and unregisters on unmount', () => {
    const view = render(<Probe commands={[cmd('test.a'), cmd('test.b')]} />)
    expect(Object.keys(useCommandStore.getState().commands)).toEqual(expect.arrayContaining(['test.a', 'test.b']))
    view.unmount()
    expect(useCommandStore.getState().commands['test.a']).toBeUndefined()
    expect(useCommandStore.getState().commands['test.b']).toBeUndefined()
  })

  it('unmounting one registration keeps another registration of the same id', () => {
    const a = cmd('test.shared')
    const b = cmd('test.shared')
    const first = render(<Probe commands={[a]} />)
    render(<Probe commands={[b]} />)
    first.unmount()
    // The second registration still owns the id.
    expect(useCommandStore.getState().commands['test.shared']).toBe(b)
  })

  it('availableCommands applies when() gates (unavailable never appears)', () => {
    render(<Probe commands={[cmd('test.on', () => true), cmd('test.off', () => false), cmd('test.throws', () => { throw new Error('x') })]} />)
    const visible = availableCommands(useCommandStore.getState().commands).map((c) => c.id)
    expect(visible).toContain('test.on')
    expect(visible).not.toContain('test.off')
    expect(visible).not.toContain('test.throws')
  })

  it('recordRun tracks recents for the empty-query palette state', () => {
    render(<Probe commands={[cmd('test.recent')]} />)
    useCommandStore.getState().recordRun('test.recent')
    useCommandStore.getState().recordRun('test.recent')
    expect(useCommandStore.getState().recents[0]).toBe('test.recent')
    expect(useCommandStore.getState().recents.filter((r) => r === 'test.recent')).toHaveLength(1)
  })
})


// Only virtual layout is substituted: settings, registry and execution are real.
vi.mock('@tanstack/react-virtual', () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getTotalSize: () => count * 36,
    getVirtualItems: () => Array.from({ length: count }, (_, index) => ({ index, key: index, start: index * 36, size: 36 })),
    scrollToIndex: () => undefined,
  }),
}))

beforeEach(() => {
  resetClientForTests()
  useCommandStore.setState({ commands: {}, recents: [], paletteOpen: false })
  useSessionStore.setState({ toasts: [] })
})

it('reloads recent visibility on open while preserving all commands and the eight-item history', async () => {
  await getClient().globalSettings.update({ navigation: { recentCommands: false } })
  const commands = Array.from({ length: 10 }, (_, i) => cmd(`item${i}`))
  render(<><Probe commands={commands} /><CommandPalette /></>)
  act(() => {
    commands.forEach((command) => useCommandStore.getState().recordRun(command.id))
    useCommandStore.getState().setPaletteOpen(true)
  })
  expect(await screen.findAllByRole('option')).toHaveLength(10)
  expect(screen.queryByText('Recent')).toBeNull()
  expect(useCommandStore.getState().recents).toHaveLength(8)
  act(() => useCommandStore.getState().setPaletteOpen(false))
  await getClient().globalSettings.update({ navigation: { recentCommands: true } })
  act(() => useCommandStore.getState().setPaletteOpen(true))
  expect(await screen.findByText('Recent')).toBeTruthy()
  expect(screen.getAllByRole('option')).toHaveLength(10)
  expect(screen.getAllByRole('option')[0].textContent).toContain('Command item9')
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'item0' } })
  expect(screen.getAllByRole('option')).toHaveLength(1)
  expect(screen.getByRole('option').textContent).toContain('Command item0')
})

it('executes once despite history storage denial and reports an independent asynchronous command failure', async () => {
  const run = vi.fn(async () => { throw new Error('Actual operation refused') })
  render(<><Probe commands={[{ ...cmd('failure'), run }]} /><CommandPalette /></>)
  act(() => useCommandStore.getState().setPaletteOpen(true))
  const option = await screen.findByRole('option')
  vi.spyOn(localStorage, 'setItem').mockImplementation(() => { throw new Error('Storage denied') })
  fireEvent.click(option)
  await waitFor(() => expect(useSessionStore.getState().toasts.map((toast) => toast.title)).toEqual(expect.arrayContaining([
    'Recent commands could not be saved', 'Command failed: Command failure',
  ])))
  expect(run).toHaveBeenCalledTimes(1)
  expect(useSessionStore.getState().toasts.find((toast) => toast.title.startsWith('Command failed'))?.body).toBe('Actual operation refused')
  expect(useCommandStore.getState().paletteOpen).toBe(false)
})

it('keeps commands available when preferences fail and retries on reopening', async () => {
  const spy = vi.spyOn(getClient().globalSettings, 'get').mockRejectedValue(new Error('Offline'))
  render(<><Probe commands={[cmd('available')]} /><CommandPalette /></>)
  act(() => useCommandStore.getState().setPaletteOpen(true))
  expect(await screen.findByRole('status')).toBeTruthy()
  expect(screen.getByRole('option').textContent).toContain('Command available')
  act(() => useCommandStore.getState().setPaletteOpen(false))
  spy.mockRestore()
  act(() => useCommandStore.getState().setPaletteOpen(true))
  await waitFor(() => expect(screen.queryByRole('status')).toBeNull())
})
