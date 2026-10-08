/**
 * Paste guard (terminal.md "Paste safety", brief §Terminal paste safety).
 *
 * Pure analysis of pasted text before it reaches the mock PTY:
 * - multiline pastes (≥ 2 lines) are confirmed when the user's
 *   `terminal.multilinePasteConfirmation` setting is on;
 * - destructive-looking patterns are ALWAYS confirmed, with a stronger
 *   warning, regardless of that setting (safety floor).
 *
 * Nothing here executes or inserts — it only describes the paste so the UI
 * can present the exact text, line count and matched risks.
 */

export interface PasteRisk {
  /** Stable id for testing + display. */
  id: string
  /** Human label for the matched risk (icon + text, never color-only). */
  label: string
  /** The regex that matched (used to highlight occurrences in the preview). */
  regex: RegExp
}

export interface PasteAnalysis {
  /** Original text, newline-normalized to `\n`. */
  text: string
  /** Individual lines (a trailing newline does not create a phantom line). */
  lines: string[]
  lineCount: number
  multiline: boolean
  /** Destructive-looking patterns found anywhere in the text. */
  risks: PasteRisk[]
  destructive: boolean
}

interface RiskDef {
  id: string
  label: string
  regex: RegExp
}

/**
 * The configurable destructive-pattern list (design: "`rm -rf`, `dd `,
 * `mkfs`, `:(){`, `> /dev/sd`, `sudo …` per configurable list" + `shutdown`).
 * Regexes carry the `g` flag so the dialog can highlight every occurrence.
 */
export const DESTRUCTIVE_PATTERNS: readonly RiskDef[] = [
  {
    id: 'rm-recursive-force',
    label: 'Recursive force delete (rm -rf)',
    regex: /\brm\s+(?:--[\w-]+\s+)*-[a-zA-Z]*(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\b/g,
  },
  { id: 'dd', label: 'Raw disk/image write (dd)', regex: /\bdd\s+(?=[a-zA-Z]+=)/g },
  { id: 'mkfs', label: 'Format a filesystem (mkfs)', regex: /\bmkfs(?:\.[\w-]+)?\b/g },
  { id: 'shutdown', label: 'Power state change (shutdown/reboot)', regex: /\b(?:shutdown|poweroff|halt|reboot)\b/g },
  { id: 'fork-bomb', label: 'Fork bomb (:(){ … })', regex: /:\s*\(\s*\)\s*\{/g },
  { id: 'raw-device', label: 'Write to a raw disk device (/dev/sd*)', regex: /(?:>\s*|\bof=)\/dev\/sd[a-z0-9]*/g },
  { id: 'sudo', label: 'Elevated privileges (sudo)', regex: /\bsudo\b/g },
  { id: 'chmod-777', label: 'World-writable permissions (chmod 777)', regex: /\bchmod\s+(?:-R\s+)?777\b/g },
]

/** Normalize pasted text: CRLF/CR → LF, strip a single trailing newline. */
export function normalizePaste(text: string): string {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
}

/** Analyze pasted text. Pure; safe to call on every paste attempt. */
export function analyzePaste(rawText: string): PasteAnalysis {
  const text = normalizePaste(rawText)
  const all = text.split('\n')
  // A trailing newline terminates the last line; it is not an extra line.
  const lines = all.length > 1 && all[all.length - 1] === '' ? all.slice(0, -1) : all
  const lineCount = lines.length
  const risks: PasteRisk[] = []
  for (const def of DESTRUCTIVE_PATTERNS) {
    def.regex.lastIndex = 0
    if (def.regex.test(text)) {
      risks.push({ id: def.id, label: def.label, regex: new RegExp(def.regex.source, 'g') })
    }
  }
  return {
    text,
    lines,
    lineCount,
    multiline: lineCount >= 2,
    risks,
    destructive: risks.length > 0,
  }
}

/**
 * Whether the paste guard interstitial must appear.
 * - Destructive content: always confirmed (stronger warning) — the setting
 *   controls multiline confirmation only, never the safety floor.
 * - Multiline: confirmed when `multilinePasteConfirmation` is on.
 */
export function pasteNeedsConfirmation(analysis: PasteAnalysis, multilinePasteConfirmation: boolean): boolean {
  if (analysis.destructive) return true
  if (analysis.multiline && multilinePasteConfirmation) return true
  return false
}

/** Highlight helper: split a preview line into segments flagged by risk matches. */
export function highlightLine(line: string, risks: readonly PasteRisk[]): { text: string; risky: boolean }[] {
  const ranges: { start: number; end: number }[] = []
  for (const risk of risks) {
    risk.regex.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = risk.regex.exec(line)) !== null) {
      if (m[0].length === 0) break
      ranges.push({ start: m.index, end: m.index + m[0].length })
    }
  }
  if (ranges.length === 0) return [{ text: line, risky: false }]
  ranges.sort((a, b) => a.start - b.start)
  const merged: { start: number; end: number }[] = []
  for (const r of ranges) {
    const last = merged[merged.length - 1]
    if (last && r.start <= last.end) last.end = Math.max(last.end, r.end)
    else merged.push({ ...r })
  }
  const segments: { text: string; risky: boolean }[] = []
  let cursor = 0
  for (const r of merged) {
    if (r.start > cursor) segments.push({ text: line.slice(cursor, r.start), risky: false })
    segments.push({ text: line.slice(r.start, r.end), risky: true })
    cursor = r.end
  }
  if (cursor < line.length) segments.push({ text: line.slice(cursor), risky: false })
  return segments
}
