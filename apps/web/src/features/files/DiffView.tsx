/**
 * DiffView (design.md §14, files.md §Save preview) — exact diff between the
 * last saved content and the pending draft, rendered with @codemirror/merge.
 * Review-only: merge/revert controls are disabled — the governed footer
 * actions (Discard / Save) are the only way through.
 *
 * `unified` renders a single read-only editor with unifiedMergeView;
 * `split` renders the side-by-side MergeView (original | pending).
 */
import { unifiedMergeView, MergeView } from '@codemirror/merge'
import { EditorState } from '@codemirror/state'
import type { Extension } from '@codemirror/state'
import { EditorView, lineNumbers } from '@codemirror/view'
import CodeMirror from '@uiw/react-codemirror'
import { useEffect, useMemo, useRef } from 'react'

import type { EditorSettings } from '@/client'

import { useEditorThemeExtension } from './editorTheme'
import { languageSupportFor } from './language'

export type DiffMode = 'unified' | 'split'

export interface DiffViewProps {
  path: string
  original: string
  modified: string
  mode: DiffMode
  settings: EditorSettings
  ariaLabel?: string
}

function useDiffBaseExtensions(path: string, settings: EditorSettings): Extension[] {
  const theme = useEditorThemeExtension({
    fontSize: settings.fontSize,
    fontFamily: settings.fontFamily,
    lineHeight: settings.lineHeight,
    ligatures: settings.ligatures,
  })
  return useMemo(
    () => [...languageSupportFor(path), theme, EditorState.readOnly.of(true), EditorView.editable.of(false)],
    [path, theme],
  )
}

function UnifiedDiff({ path, original, modified, settings, ariaLabel }: DiffViewProps) {
  const base = useDiffBaseExtensions(path, settings)
  const extensions = useMemo(
    () => [
      ...base,
      unifiedMergeView({
        original,
        highlightChanges: true,
        gutter: true,
        mergeControls: false,
        collapseUnchanged: { margin: 3, minSize: 6 },
      }),
    ],
    [base, original],
  )
  return (
    <CodeMirror
      value={modified}
      theme="none"
      readOnly
      editable={false}
      aria-label={ariaLabel ?? `Diff of ${path}`}
      height="100%"
      style={{ height: '100%' }}
      basicSetup={{
        lineNumbers: true,
        highlightActiveLine: false,
        highlightActiveLineGutter: false,
        foldGutter: false,
        drawSelection: false,
        history: false,
        searchKeymap: false,
        autocompletion: false,
        closeBrackets: false,
        bracketMatching: false,
        indentOnInput: false,
      }}
      extensions={extensions}
    />
  )
}

function SplitDiff({ path, original, modified, settings, ariaLabel }: DiffViewProps) {
  const base = useDiffBaseExtensions(path, settings)
  const containerRef = useRef<HTMLDivElement>(null)
  const viewRef = useRef<MergeView | null>(null)

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    const view = new MergeView({
      a: { doc: original, extensions: [...base, lineNumbers()] },
      b: { doc: modified, extensions: [...base, lineNumbers()] },
      orientation: 'a-b',
      highlightChanges: true,
      gutter: true,
      collapseUnchanged: { margin: 3, minSize: 6 },
    })
    container.appendChild(view.dom)
    viewRef.current = view
    return () => {
      view.destroy()
      viewRef.current = null
      container.replaceChildren()
    }
  }, [base, original, modified])

  return (
    <div
      ref={containerRef}
      aria-label={ariaLabel ?? `Side-by-side diff of ${path}`}
      className="h-full overflow-auto [&_.cm-mergeView]:h-full [&_.cm-mergeViewEditors]:h-full"
      data-testid="split-diff"
    />
  )
}

export function DiffView(props: DiffViewProps) {
  return props.mode === 'split' ? <SplitDiff {...props} /> : <UnifiedDiff {...props} />
}
