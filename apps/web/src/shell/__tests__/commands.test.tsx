/**
 * Command registry — useRegisterCommands registers for the component's
 * lifetime and auto-unregisters on unmount (the feature-agent contract).
 */
import { cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

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
