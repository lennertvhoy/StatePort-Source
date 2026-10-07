/**
 * Transcript export helpers (terminal.md: exports are explicit, .txt download).
 */

/** Trigger a browser download of a text file. */
export function downloadTextFile(filename: string, text: string): void {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** `<session-name>-<yyyy-mm-dd-hh-mm-ss>.txt` */
export function exportFilenameFor(sessionName: string): string {
  const slug = sessionName.trim().replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '') || 'terminal'
  const stamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')
  return `${slug}-${stamp}.txt`
}
