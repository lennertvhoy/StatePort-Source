import { afterEach, expect, it } from 'vitest'
import { EditorState } from '@codemirror/state'
import { EditorView } from '@codemirror/view'
import { buildEditorTheme } from '../editorTheme'

let view: EditorView | undefined
let host: HTMLDivElement | undefined
afterEach(() => { view?.destroy(); host?.remove() })

it.each([
  ['system', 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace'],
  ['JetBrains Mono', 'JetBrains Mono'],
  ['Custom Monospace', 'Custom Monospace'],
])('renders %s using the intended editor font family without modifying the document', (fontFamily, expected) => {
  host = document.createElement('div')
  document.body.appendChild(host)
  const doc = 'const unchanged = "=>"'
  view = new EditorView({ parent: host, state: EditorState.create({ doc, extensions: buildEditorTheme({ fontFamily, fontSize: 13, lineHeight: 1.5, ligatures: false }) }) })
  expect(getComputedStyle(view.contentDOM).fontFamily.replaceAll('"', '')).toBe(expected)
  expect(getComputedStyle(view.scrollDOM).fontFamily.replaceAll('"', '')).toBe(expected)
  expect(view.state.doc.toString()).toBe(doc)
})
