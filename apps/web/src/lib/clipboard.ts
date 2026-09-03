/**
 * Clipboard helper shared by CopyButton and feature surfaces. Lives outside
 * component modules so fast-refresh boundaries stay component-only.
 */

/** Copy text to the clipboard; resolves false instead of throwing. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    // Clipboard API unavailable (non-secure context / tests) — textarea fallback.
    try {
      const el = document.createElement('textarea')
      el.value = text
      el.style.position = 'fixed'
      el.style.opacity = '0'
      document.body.appendChild(el)
      el.select()
      document.execCommand('copy')
      document.body.removeChild(el)
      return true
    } catch {
      return false
    }
  }
}
