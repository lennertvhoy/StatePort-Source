import { describe, expect, it } from 'vitest'

import {
  MAX_SETTINGS_IMPORT_BYTES,
  assertSettingsImportSize,
  settingsImportByteLength,
} from './settingsImportPolicy'
import { ClientError } from './types'

describe('settings import resource policy', () => {
  it('measures UTF-8 bytes and accepts a bounded export', () => {
    expect(settingsImportByteLength('{"label":"é"}')).toBe(
      new TextEncoder().encode('{"label":"é"}').length,
    )
    expect(() => assertSettingsImportSize('{}')).not.toThrow()
  })

  it('rejects an oversized import before JSON parsing', () => {
    const payload = 'x'.repeat(MAX_SETTINGS_IMPORT_BYTES + 1)
    let error: unknown
    try {
      assertSettingsImportSize(payload)
    } catch (candidate) {
      error = candidate
    }
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })
})
