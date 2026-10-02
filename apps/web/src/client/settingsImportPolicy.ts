import { ClientError } from './types'

/** Settings exports are small; bound imports before parsing or merging them. */
export const MAX_SETTINGS_IMPORT_BYTES = 256 * 1024

export function settingsImportByteLength(value: string): number {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(value).length
  // Conservative fallback: UTF-16 code units never undercount ASCII and may
  // reject a non-ASCII payload slightly early, which is safe at this boundary.
  return value.length * 2
}

export function assertSettingsImportSize(value: string): void {
  const bytes = settingsImportByteLength(value)
  if (bytes > MAX_SETTINGS_IMPORT_BYTES) {
    throw new ClientError('validation', 'Settings import is too large', {
      detail: `Settings imports are limited to ${MAX_SETTINGS_IMPORT_BYTES} bytes; this file is ${bytes} bytes.`,
    })
  }
}
