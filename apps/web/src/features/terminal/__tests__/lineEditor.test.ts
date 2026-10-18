/**
 * LineEditor — the mock-PTY prompt editor: echo, backspace (incl. joining
 * pasted lines), history, cancel/clear, and the guarantee that only Enter
 * submits (inserted text never runs by itself).
 */
import { describe, expect, it, vi } from 'vitest'

import { LineEditor } from '../lineEditor'

const PROMPT = 'kim@stateport:~/app$ '

function makeEditor(overrides?: Partial<ConstructorParameters<typeof LineEditor>[0]>) {
  const onSubmit = vi.fn()
  const editor = new LineEditor({
    prompt: () => PROMPT,
    promptColumns: () => PROMPT.length,
    onSubmit,
    ...overrides,
  })
  return { editor, onSubmit }
}

describe('LineEditor typing', () => {
  it('echoes printable input and submits on Enter only', () => {
    const { editor, onSubmit } = makeEditor()
    const ops = editor.input('git status')
    expect(ops.join('')).toBe('git status')
    expect(onSubmit).not.toHaveBeenCalled()
    const enterOps = editor.input('\r')
    expect(enterOps).toEqual(['\r\n'])
    expect(onSubmit).toHaveBeenCalledTimes(1)
    expect(onSubmit).toHaveBeenCalledWith('git status')
    expect(editor.buffer).toBe('')
  })

  it('backspace erases one char with the erase op', () => {
    const { editor } = makeEditor()
    editor.input('lst')
    const ops = editor.input('\x7f')
    expect(ops).toEqual(['\b \b'])
    expect(editor.buffer).toBe('ls')
  })

  it('backspace on an empty buffer is a no-op', () => {
    const { editor } = makeEditor()
    expect(editor.input('\x7f')).toEqual([])
  })

  it('Ctrl+C cancels the line and re-prompts', () => {
    const { editor, onSubmit } = makeEditor()
    editor.input('rm -rf /')
    const ops = editor.input('\x03')
    expect(ops).toEqual(['^C', '\r\n', PROMPT])
    expect(editor.buffer).toBe('')
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it('Ctrl+U erases the buffer with per-char erase ops', () => {
    const { editor } = makeEditor()
    editor.input('abc')
    const ops = editor.input('\x15')
    expect(ops).toEqual(['\b \b', '\b \b', '\b \b'])
    expect(editor.buffer).toBe('')
  })

  it('Ctrl+L clears the screen and redraws prompt + buffer', () => {
    const { editor } = makeEditor()
    editor.input('git')
    const ops = editor.input('\x0c')
    expect(ops).toEqual(['\x1b[2J\x1b[H', PROMPT, 'git'])
  })

  it('ignores arrow-left/right and tab (no cursor movement, no completion)', () => {
    const { editor } = makeEditor()
    editor.input('ab')
    expect(editor.input('\x1b[D')).toEqual([])
    expect(editor.input('\t')).toEqual([])
    expect(editor.buffer).toBe('ab')
  })
})

describe('LineEditor history', () => {
  it('recalls submitted lines with Up/Down and restores the stash', () => {
    const { editor } = makeEditor()
    editor.input('pwd')
    editor.input('\r')
    editor.input('ls')
    editor.input('\r')
    editor.input('ca')
    // Up → 'ls', replacing the in-progress 'ca' (stashed)
    let ops = editor.input('\x1b[A')
    expect(ops).toEqual(['\b \b', '\b \b', 'ls'])
    expect(editor.buffer).toBe('ls')
    // Up → 'pwd'
    ops = editor.input('\x1b[A')
    expect(ops).toEqual(['\b \b', '\b \b', 'pwd'])
    // Down → 'ls', Down → stash 'ca'
    editor.input('\x1b[B')
    ops = editor.input('\x1b[B')
    expect(editor.buffer).toBe('ca')
    expect(ops[ops.length - 1]).toBe('ca')
  })

  it('does not record blank lines', () => {
    const { editor } = makeEditor()
    editor.input('\r')
    expect(editor.historyEntries).toEqual([])
  })
})

describe('LineEditor paste insertion (review-first)', () => {
  it('insertText echoes but NEVER submits', () => {
    const { editor, onSubmit } = makeEditor()
    const ops = editor.insertText('git status\nrm -rf /')
    expect(ops).toEqual(['git status\r\nrm -rf /'])
    expect(editor.buffer).toBe('git status\nrm -rf /')
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it('backspace over an inserted newline joins lines (up + to end of previous line)', () => {
    const { editor } = makeEditor()
    editor.insertText('ab\ncd\n')
    // buffer: "ab\ncd\n" — cursor at col 0 of the empty line after "cd"
    const ops = editor.input('\x7f')
    // delete trailing '\n' → move up to end of "cd" (2 columns)
    expect(ops).toEqual(['\x1b[A\x1b[2C'])
    expect(editor.buffer).toBe('ab\ncd')
    // now erase 'd' and 'c' as plain chars
    expect(editor.input('\x7f')).toEqual(['\b \b'])
    expect(editor.input('\x7f')).toEqual(['\b \b'])
    // erase the remaining newline → up to end of first line:
    // first visual line includes the prompt width + "ab" (PROMPT.length + 2)
    const joinOps = editor.input('\x7f')
    expect(joinOps).toEqual([`\x1b[A\x1b[${PROMPT.length + 2}C`])
    expect(editor.buffer).toBe('ab')
  })

  it('a multiline buffer submits as ONE line only when the user presses Enter', () => {
    const { editor, onSubmit } = makeEditor()
    editor.insertText('echo one\necho two')
    editor.input('\r')
    expect(onSubmit).toHaveBeenCalledTimes(1)
    expect(onSubmit).toHaveBeenCalledWith('echo one\necho two')
  })
})
