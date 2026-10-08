/**
 * Terminal output is untrusted. Only absolute HTTP(S) destinations may cross
 * the browser navigation boundary; every other value remains copy-only.
 */

export interface TerminalLinkDecision {
  original: string
  href?: string
  refusal?: string
}

type ExternalOpener = (
  url?: string | URL,
  target?: string,
  features?: string,
) => Window | null

export function validateTerminalLink(value: string): TerminalLinkDecision {
  const hasControlCharacter = [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0
    return code <= 31 || code === 127
  })
  if (!value || value.length > 2048 || value !== value.trim() || hasControlCharacter) {
    return {
      original: value,
      refusal: 'The terminal reported a malformed or unbounded destination.',
    }
  }
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return {
      original: value,
      refusal: 'The terminal reported a malformed destination.',
    }
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      original: value,
      refusal: `The ${parsed.protocol || 'unknown'} scheme is not allowed. Only http(s) links can be opened.`,
    }
  }
  if (parsed.username || parsed.password) {
    return {
      original: value,
      refusal: 'Links containing embedded credentials are not opened.',
    }
  }
  return { original: value, href: parsed.href }
}

export function openTerminalLink(
  decision: TerminalLinkDecision,
  opener: ExternalOpener = (url, target, features) =>
    window.open(url, target, features),
): boolean {
  if (!decision.href) return false
  const opened = opener(decision.href, '_blank', 'noopener,noreferrer')
  if (opened) opened.opener = null
  return true
}
