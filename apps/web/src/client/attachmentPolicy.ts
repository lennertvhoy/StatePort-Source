/**
 * The single authoritative attachment policy (contract §14).
 *
 * The backend (`ConversationAttachmentStore`) enforces exactly these limits
 * server-side; the UI gate, the mock adapter, and the http adapter all share
 * this module so a file the interface declares valid is never rejected by
 * the service, and a file the service would reject is never offered.
 */

/** Contract §14: 2 MiB per attachment, validated before upload. */
export const MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024

/** Contract §14 supported attachment media types (backend allowlist). */
export const ALLOWED_ATTACHMENT_TYPES: readonly string[] = [
  'text/plain',
  'text/markdown',
  'application/json',
  'text/yaml',
  'application/yaml',
  'application/x-yaml',
  'image/png',
  'image/jpeg',
  'application/pdf',
]

export const ATTACHMENT_LIMIT_HINT = 'PNG/JPEG images, PDFs, JSON, YAML, Markdown, and plain text up to 2 MiB'

/** Attachments remain local conversation records; they are not model context. */
export const ATTACHMENT_CONTEXT_NOTE = 'Attachments are stored with the conversation and are not sent to the assistant.'

export type AttachmentCheck = { ok: true } | { ok: false; reason: string }

/** Client-side gate before an upload starts; the service re-validates. */
export function checkAttachment(name: string, mimeType: string, sizeBytes: number): AttachmentCheck {
  if (sizeBytes > MAX_ATTACHMENT_BYTES) {
    const mib = (sizeBytes / (1024 * 1024)).toFixed(1)
    return { ok: false, reason: `“${name}” is ${mib} MiB — attachments are limited to 2 MiB.` }
  }
  if (!ALLOWED_ATTACHMENT_TYPES.includes(mimeType)) {
    const reportedType = mimeType ? `The browser reported ${mimeType}.` : 'The browser did not report a file type.'
    return {
      ok: false,
      reason: `“${name}” has an unsupported file type. ${reportedType} Only ${ATTACHMENT_LIMIT_HINT}.`,
    }
  }
  return { ok: true }
}
