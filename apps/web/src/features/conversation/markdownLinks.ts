/**
 * Assistant-authored Markdown is untrusted input. Keep links inert unless the
 * browser resolves them to HTTP(S); in particular, never pass javascript:,
 * data:, file:, or custom schemes through to an anchor.
 */
export function safeMarkdownUrl(value: string): string {
  const candidate = value.trim()
  const hasControlCharacter = Array.from(candidate).some((character) => {
    const code = character.charCodeAt(0)
    return code <= 31 || code === 127
  })
  if (!candidate || candidate !== value || candidate.length > 2048 || hasControlCharacter) return ''
  try {
    const parsed = new URL(candidate, 'https://stateport.invalid/')
    return (
      (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      !parsed.username &&
      !parsed.password
    ) ? candidate : ''
  } catch {
    return ''
  }
}
