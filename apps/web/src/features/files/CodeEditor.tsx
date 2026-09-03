/**
 * CodeEditor — the CodeMirror 6 editor for the Files tool (files.md §Editor).
 *
 * - Language by extension (installed @codemirror/lang-* + legacy nix mode).
 * - Theme is built from live CSS tokens (editorTheme.ts) so light/dark/HC
 *   follow the interface appearance automatically.
 * - Font size/family/line-height/ligatures/tab size/word wrap come from the
 *   editor settings (workspace-level settings, workspace store continuity).
 * - Find & replace via @codemirror/search (files.find opens the panel).
 * - Cursor position + selection are reported out so the tool can persist
 *   cursor per file and offer "Send selection to Conversation".
 * - Read-only files stay fully selectable/copyable but never editable.
 */
import { indentUnit } from '@codemirror/language'
import { highlightSelectionMatches, search } from '@codemirror/search'
import { EditorState } from '@codemirror/state'
import type { Extension } from '@codemirror/state'
import { EditorView, keymap } from '@codemirror/view'
import type { ViewUpdate } from '@codemirror/view'
import CodeMirror from '@uiw/react-codemirror'
import { useCallback, useEffect, useMemo } from 'react'

import type { EditorSettings } from '@/client'

import type { EditorFontSpec } from './editorTheme'
import { useEditorThemeExtension } from './editorTheme'
import { languageSupportFor } from './language'

export interface EditorSelectionInfo {
  text: string
  lineStart: number
  lineEnd: number
}

export interface EditorCursor {
  line: number
  column: number
}

export interface CodeEditorProps {
  path: string
  value: string
  readOnly: boolean
  ariaLabel: string
  settings: EditorSettings
  wordWrap: boolean
  /** Restored cursor position (workspace store), applied on create. */
  initialCursor?: EditorCursor | null
  onChangeValue: (value: string) => void
  onCursor?: (cursor: EditorCursor) => void
  onSelectionChange?: (selection: EditorSelectionInfo | null) => void
  /** Register the live EditorView (null on unmount) for tool commands. */
  onRegisterView?: (view: EditorView | null) => void
}

function cursorOf(view: EditorView): EditorCursor {
  const head = view.state.selection.main.head
  const line = view.state.doc.lineAt(head)
  return { line: line.number, column: head - line.from + 1 }
}

function selectionOf(view: EditorView): EditorSelectionInfo | null {
  const { from, to } = view.state.selection.main
  if (from === to) return null
  const text = view.state.sliceDoc(from, to)
  if (!text) return null
  const start = view.state.doc.lineAt(from)
  const end = view.state.doc.lineAt(to)
  return { text, lineStart: start.number, lineEnd: end.number }
}

export function CodeEditor({
  path,
  value,
  readOnly,
  ariaLabel,
  settings,
  wordWrap,
  initialCursor,
  onChangeValue,
  onCursor,
  onSelectionChange,
  onRegisterView,
}: CodeEditorProps) {
  const font = useMemo<EditorFontSpec>(
    () => ({
      fontSize: settings.fontSize,
      fontFamily: settings.fontFamily,
      lineHeight: settings.lineHeight,
      ligatures: settings.ligatures,
    }),
    [settings.fontSize, settings.fontFamily, settings.lineHeight, settings.ligatures],
  )
  const theme = useEditorThemeExtension(font)

  const extensions = useMemo<Extension[]>(() => {
    const list: Extension[] = [
      ...languageSupportFor(path),
      theme,
      indentUnit.of(settings.indentWith === 'tabs' ? '\t' : ' '.repeat(settings.tabSize)),
      EditorState.tabSize.of(settings.tabSize),
      highlightSelectionMatches(),
      search({ top: true }),
    ]
    if (wordWrap) list.push(EditorView.lineWrapping)
    if (readOnly) list.push(EditorState.readOnly.of(true), EditorView.editable.of(false))
    // Keep Tab as indentation inside the editor (design.md keyboard rules).
    list.push(keymap.of([]))
    return list
  }, [path, theme, settings.indentWith, settings.tabSize, wordWrap, readOnly])

  const handleUpdate = useCallback(
    (update: ViewUpdate) => {
      if (update.selectionSet || update.docChanged) {
        onCursor?.(cursorOf(update.view))
        onSelectionChange?.(selectionOf(update.view))
      }
      if (update.docChanged && update.view.hasFocus) {
        onSelectionChange?.(selectionOf(update.view))
      }
    },
    [onCursor, onSelectionChange],
  )

  const handleCreate = useCallback(
    (view: EditorView) => {
      onRegisterView?.(view)
      if (initialCursor) {
        const maxLine = view.state.doc.lines
        const line = view.state.doc.line(Math.min(Math.max(initialCursor.line, 1), maxLine))
        const pos = Math.min(line.from + Math.max(initialCursor.column - 1, 0), line.to)
        view.dispatch({ selection: { anchor: pos } })
      }
    },
    [onRegisterView, initialCursor],
  )

  useEffect(() => () => onRegisterView?.(null), [onRegisterView])

  return (
    <CodeMirror
      value={value}
      height="100%"
      style={{ height: '100%' }}
      theme="none"
      aria-label={ariaLabel}
      readOnly={readOnly}
      editable={!readOnly}
      extensions={extensions}
      basicSetup={{
        lineNumbers: true,
        highlightActiveLine: true,
        highlightActiveLineGutter: true,
        foldGutter: true,
        drawSelection: true,
        indentOnInput: true,
        bracketMatching: true,
        closeBrackets: settings.autoCloseBrackets,
        autocompletion: true,
        searchKeymap: true,
        highlightSelectionMatches: false,
        history: true,
      }}
      indentWithTab
      onChange={(next) => onChangeValue(next)}
      onUpdate={handleUpdate}
      onCreateEditor={handleCreate}
    />
  )
}
