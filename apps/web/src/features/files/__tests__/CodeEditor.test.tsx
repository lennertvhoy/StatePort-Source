import { cleanup, render, waitFor } from '@testing-library/react'
import { EditorState } from '@codemirror/state'
import { EditorView } from '@codemirror/view'
import { afterEach, expect, it, vi } from 'vitest'

import type { EditorSettings } from '@/client'
import { CodeEditor } from '../CodeEditor'

const settings: EditorSettings = {
  fontFamily: 'JetBrains Mono', fontSize: 13, lineHeight: 1.5,
  tabSize: 2, indentWith: 'spaces', wordWrap: true, minimap: false,
  ligatures: false, formatOnSave: false, autoCloseBrackets: true,
  showWhitespace: false, previewDiffBeforeSave: true, restoreOpenFiles: true,
  restoreCursorPositions: true, autosave: false,
}

afterEach(cleanup)

it('toggles visible spaces and tabs in the actual editor without editing the document or selection', async () => {
  const value = 'const\tname = "a b";\n'
  const onChangeValue = vi.fn()
  const registered = vi.fn()
  const props = { path: 'sample.ts', value, readOnly: false, ariaLabel: 'Sample file', settings,
    wordWrap: false, initialCursor: { line: 1, column: 5 }, onChangeValue, onRegisterView: registered }
  const ui = render(<CodeEditor {...props} />)
  await waitFor(() => expect(registered).toHaveBeenCalled())
  const view = registered.mock.calls[0][0] as EditorView
  const selection = view.state.selection.toJSON()
  expect(ui.container.querySelector('.cm-highlightSpace')).toBeNull()
  expect(ui.container.querySelector('.cm-highlightTab')).toBeNull()
  ui.rerender(<CodeEditor {...props} settings={{ ...settings, showWhitespace: true }} />)
  await waitFor(() => expect(ui.container.querySelector('.cm-highlightSpace')).not.toBeNull())
  expect(ui.container.querySelector('.cm-highlightTab')).not.toBeNull()
  expect(view.state.doc.toString()).toBe(value)
  expect(view.state.selection.toJSON()).toEqual(selection)
  expect(onChangeValue).not.toHaveBeenCalled()
  ui.rerender(<CodeEditor {...props} />)
  await waitFor(() => expect(ui.container.querySelector('.cm-highlightSpace')).toBeNull())
  expect(ui.container.querySelector('.cm-highlightTab')).toBeNull()
  expect(view.state.doc.toString()).toBe(value)
  expect(onChangeValue).not.toHaveBeenCalled()
})

it('shows whitespace in read-only files while preserving their read-only editor contract', async () => {
  const onChangeValue = vi.fn()
  const registered = vi.fn()
  const ui = render(<CodeEditor path="protected.txt" value={'one two\tthree'} readOnly ariaLabel="Protected file"
    settings={{ ...settings, showWhitespace: true }} wordWrap onChangeValue={onChangeValue} onRegisterView={registered} />)
  await waitFor(() => expect(ui.container.querySelector('.cm-highlightTab')).not.toBeNull())
  const view = registered.mock.calls[0][0] as EditorView
  expect(view.state.facet(EditorState.readOnly)).toBe(true)
  expect(view.state.facet(EditorView.editable)).toBe(false)
  expect(ui.container.querySelector('.cm-content')?.getAttribute('contenteditable')).toBe('false')
  expect(view.state.doc.toString()).toBe('one two\tthree')
  expect(onChangeValue).not.toHaveBeenCalled()
})
