/**
 * CodeMirror theme built from the live design tokens (files.md §Editor):
 * reads getComputedStyle tokens so light / dark / high-contrast themes are
 * followed automatically — no per-theme CodeMirror config anywhere.
 *
 * `useEditorThemeExtension` rebuilds the extension whenever the document
 * theme attributes change (data-theme / data-hc-base / class).
 */
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import type { Extension } from '@codemirror/state'
import { EditorView } from '@codemirror/view'
import { tags } from '@lezer/highlight'
import { useEffect, useMemo, useState } from 'react'

export interface EditorFontSpec {
  fontSize: number
  fontFamily: string
  lineHeight: number
  ligatures: boolean
}

function token(name: string, fallback: string): string {
  if (typeof document === 'undefined') return fallback
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return value || fallback
}

/** Relative luminance of a #rgb/#rrggbb color (0 = black, 1 = white). */
function luminance(color: string): number {
  const hex = color.replace('#', '')
  if (!/^[0-9a-fA-F]{3}$|^[0-9a-fA-F]{6}$/.test(hex)) return 1
  const full = hex.length === 3 ? hex.split('').map((c) => c + c).join('') : hex
  const r = parseInt(full.slice(0, 2), 16) / 255
  const g = parseInt(full.slice(2, 4), 16) / 255
  const b = parseInt(full.slice(4, 6), 16) / 255
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

/** Build the CodeMirror theme + syntax highlight extensions from tokens. */
export function buildEditorTheme(font: EditorFontSpec): Extension {
  const bg = token('--bg-sunken', '#F6F6F4')
  const fg = token('--text-primary', '#262B31')
  const secondary = token('--text-secondary', '#57606A')
  const tertiary = token('--text-tertiary', '#67717C')
  const hover = token('--bg-hover', '#F0F0ED')
  const surface = token('--bg-surface', '#FFFFFF')
  const border = token('--border-default', '#E3E3DE')
  const borderStrong = token('--border-strong', '#C9C9C2')
  const accent = token('--accent', '#2E5AAC')
  const accentSoft = token('--accent-soft-bg', '#E8EEF9')
  const success = token('--status-success-text', '#256B43')
  const attention = token('--status-attention-text', '#8A6100')
  const attentionBg = token('--status-attention-bg', '#F8F0DC')
  const waiting = token('--status-waiting-text', '#5748B5')
  const blocked = token('--status-blocked-text', '#9C4A20')
  const danger = token('--status-danger-text', '#B3261E')
  const successBg = token('--status-success-bg', '#EAF4EE')
  const dangerBg = token('--status-danger-bg', '#F9E5E3')
  const dark = luminance(bg) < 0.5

  const theme = EditorView.theme(
    {
      '&': {
        backgroundColor: bg,
        color: fg,
        fontSize: `${font.fontSize}px`,
        height: '100%',
      },
      '.cm-content': {
        fontFamily: font.fontFamily,
        lineHeight: String(font.lineHeight),
        caretColor: accent,
        // Ligatures are opt-in (design.md §4.1) — off unless the setting says so.
        fontFeatureSettings: font.ligatures ? 'normal' : '"liga" 0, "calt" 0',
        paddingBottom: '24px',
      },
      '.cm-cursor, .cm-dropCursor': { borderLeftColor: accent },
      '&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground': {
        backgroundColor: accentSoft,
      },
      '.cm-selectionMatch': { backgroundColor: 'transparent', outline: `1px solid ${borderStrong}` },
      '.cm-matchingBracket': { backgroundColor: 'transparent', outline: `1px solid ${accent}` },
      '.cm-nonmatchingBracket': { outline: `1px solid ${danger}` },
      '.cm-gutters': {
        backgroundColor: bg,
        color: tertiary,
        border: 'none',
        borderRight: `1px solid ${border}`,
      },
      '.cm-lineNumbers .cm-gutterElement': { minWidth: '3ch', padding: '0 8px 0 12px' },
      '.cm-activeLine': { backgroundColor: hover },
      '.cm-activeLineGutter': { backgroundColor: hover, color: fg },
      '.cm-foldGutter': { color: tertiary },
      '.cm-searchMatch': { backgroundColor: attentionBg, outline: `1px solid ${attention}` },
      '.cm-searchMatch.cm-searchMatch-selected': { backgroundColor: attention, color: surface },
      '.cm-panels': {
        backgroundColor: surface,
        color: fg,
        borderTop: `1px solid ${border}`,
        borderBottom: 'none',
      },
      '.cm-panels input, .cm-panels button, .cm-panels select': {
        backgroundColor: surface,
        color: fg,
        border: `1px solid ${borderStrong}`,
        borderRadius: '4px',
        fontSize: '12px',
      },
      '.cm-panels button': { cursor: 'pointer', padding: '1px 8px' },
      '.cm-panels input[type="checkbox"]': { border: 'none' },
      '.cm-textfield': { padding: '2px 6px' },
      '.cm-button': { backgroundImage: 'none', backgroundColor: hover },
      '.cm-tooltip': {
        backgroundColor: surface,
        color: fg,
        border: `1px solid ${border}`,
        borderRadius: '6px',
      },
      '.cm-tooltip.cm-tooltip-autocomplete > ul > li[aria-selected]': {
        backgroundColor: accentSoft,
        color: fg,
      },
      '.cm-completionIcon': { color: tertiary },
      '.cm-completionDetail': { color: tertiary, fontStyle: 'normal' },
      '.cm-completionMatchedText': { color: accent, textDecoration: 'none', fontWeight: '600' },
      '.cm-placeholder': { color: tertiary },
      '&.cm-focused': { outline: 'none' },
      '.cm-scroller': { fontFamily: font.fontFamily },
    },
    { dark },
  )

  const highlight = HighlightStyle.define([
    { tag: tags.comment, color: tertiary, fontStyle: 'italic' },
    { tag: [tags.keyword, tags.modifier, tags.controlKeyword], color: accent },
    { tag: [tags.string, tags.special(tags.string), tags.regexp], color: success },
    { tag: [tags.number, tags.bool, tags.null, tags.atom], color: waiting },
    { tag: [tags.function(tags.variableName), tags.function(tags.propertyName)], color: accent },
    { tag: [tags.propertyName, tags.attributeName, tags.labelName], color: attention },
    { tag: [tags.typeName, tags.className, tags.tagName, tags.namespace], color: blocked },
    { tag: [tags.operator, tags.punctuation, tags.separator], color: secondary },
    { tag: [tags.variableName, tags.name], color: fg },
    { tag: [tags.definition(tags.variableName), tags.definition(tags.propertyName)], color: fg },
    { tag: [tags.heading, tags.strong], color: fg, fontWeight: '600' },
    { tag: tags.emphasis, fontStyle: 'italic' },
    { tag: tags.link, color: accent, textDecoration: 'underline' },
    { tag: [tags.monospace], color: success },
    { tag: tags.quote, color: tertiary, fontStyle: 'italic' },
    { tag: tags.strikethrough, textDecoration: 'line-through' },
    { tag: tags.invalid, color: danger, textDecoration: 'underline wavy' },
    // Merge/diff tints (files.md DiffView: added/removed line tints).
    { tag: tags.inserted, backgroundColor: successBg },
    { tag: tags.deleted, backgroundColor: dangerBg },
  ])

  return [theme, syntaxHighlighting(highlight)]
}

/**
 * The editor theme extension, rebuilt when the document theme changes so
 * light/dark/HC follow the interface appearance automatically.
 */
export function useEditorThemeExtension(font: EditorFontSpec): Extension {
  const [themeEpoch, setThemeEpoch] = useState(0)
  useEffect(() => {
    if (typeof document === 'undefined' || typeof MutationObserver === 'undefined') return
    const observer = new MutationObserver(() => setThemeEpoch((e) => e + 1))
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme', 'data-hc-base', 'class', 'style'],
    })
    return () => observer.disconnect()
  }, [])
  const { fontSize, fontFamily, lineHeight, ligatures } = font
  return useMemo(() => {
    // themeEpoch forces a rebuild when the document theme attributes change.
    void themeEpoch
    return buildEditorTheme({ fontSize, fontFamily, lineHeight, ligatures })
  }, [themeEpoch, fontSize, fontFamily, lineHeight, ligatures])
}
