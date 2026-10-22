/**
 * Accepting the free-model terms binds the consent to the exact text shown:
 * the service digest is sent back unchanged, and when the browser can hash,
 * the text on screen must match that digest first (fail closed otherwise).
 */
import { ClientError } from '@/client'
import { getModelsClient, type ModelConsent } from '@/client/modelsClient'
import { sameSha256, sha256Hex } from '@/lib/sha256'

export async function acceptFreeModelTerms(consent: ModelConsent): Promise<void> {
  const computed = await sha256Hex(consent.terms.text)
  if (computed !== null && !sameSha256(computed, consent.terms.sha256)) {
    throw new ClientError(
      'validation',
      'The terms text on this page does not match the digest the service recorded. Reload the page and review the terms again.',
    )
  }
  await getModelsClient().grantConsent({ destination: consent.destination, termsSha256: consent.terms.sha256 })
}
