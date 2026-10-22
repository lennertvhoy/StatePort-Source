/**
 * SHA-256 of a UTF-8 string as lowercase hex, or `null` when the browser
 * offers no Web Crypto digest (non-secure contexts). Callers treat `null` as
 * "could not check locally", never as a match.
 */
export async function sha256Hex(text: string): Promise<string | null> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle || typeof subtle.digest !== 'function') return null
  try {
    const bytes = new TextEncoder().encode(text)
    const digest = await subtle.digest('SHA-256', bytes)
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
  } catch {
    return null
  }
}

/** Compare a computed hex digest with a service digest (`<hex>` or `sha256:<hex>`). */
export function sameSha256(computedHex: string, serviceDigest: string): boolean {
  return computedHex === serviceDigest.replace(/^sha256:/, '').toLowerCase()
}
