/**
 * Commands that operate on a live CodeMirror EditorView (kept out of
 * component modules so fast refresh stays happy).
 */
import { openSearchPanel } from '@codemirror/search'
import type { EditorView } from '@codemirror/view'

/** Open the find & replace panel in a registered view (files.find). */
export function openFindInView(view: EditorView | null | undefined): boolean {
  if (!view) return false
  view.focus()
  return openSearchPanel(view)
}
