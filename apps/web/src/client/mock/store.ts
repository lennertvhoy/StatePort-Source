/**
 * Mock persistence layer.
 *
 * - Namespaced key `stateport.mock.v1` in localStorage. No IndexedDB store or
 *   second browser-state authority exists.
 * - Debounced writes so rapid mock transitions don't thrash storage.
 * - Versioned envelope: unknown version or corrupt payload ⇒ reseed.
 * - `resetMockState()` wipes and re-seeds deterministically.
 */
import { z } from 'zod'

export const MOCK_STORAGE_KEY = 'stateport.mock.v1'
export const MOCK_STATE_VERSION = 1

const envelopeSchema = z.object({
  version: z.number().int(),
  savedAt: z.string(),
  /** Opaque payload — validated in depth by the mock adapter on load. */
  data: z.unknown(),
})

interface Envelope {
  version: number
  savedAt: string
  data: unknown
}

let writeTimer: ReturnType<typeof setTimeout> | null = null
const DEBOUNCE_MS = 120

function storageAvailable(): boolean {
  try {
    return typeof window !== 'undefined' && !!window.localStorage
  } catch {
    return false
  }
}

/** Load and validate the envelope. Returns null when absent/corrupt/stale. */
export function loadMockEnvelope(): Envelope | null {
  if (!storageAvailable()) return null
  const raw = window.localStorage.getItem(MOCK_STORAGE_KEY)
  if (!raw) return null
  try {
    const parsed = envelopeSchema.safeParse(JSON.parse(raw))
    if (!parsed.success) return null
    if (parsed.data.version !== MOCK_STATE_VERSION) return null
    return parsed.data
  } catch {
    return null
  }
}

/** Debounced persist. Call `flushMockWrites()` in tests to force a write. */
export function saveMockEnvelope(data: unknown, savedAtMs = Date.now()): void {
  if (!storageAvailable()) return
  if (writeTimer) clearTimeout(writeTimer)
  writeTimer = setTimeout(() => {
    writeTimer = null
    const envelope: Envelope = {
      version: MOCK_STATE_VERSION,
      savedAt: new Date(savedAtMs).toISOString(),
      data,
    }
    try {
      window.localStorage.setItem(MOCK_STORAGE_KEY, JSON.stringify(envelope))
    } catch {
      // Quota exceeded: the mock stays functional in-memory for the session.
    }
  }, DEBOUNCE_MS)
}

export function flushMockWrites(data?: unknown, savedAtMs = Date.now()): void {
  if (writeTimer) {
    clearTimeout(writeTimer)
    writeTimer = null
  }
  if (data !== undefined && storageAvailable()) {
    const envelope: Envelope = {
      version: MOCK_STATE_VERSION,
      savedAt: new Date(savedAtMs).toISOString(),
      data,
    }
    try {
      window.localStorage.setItem(MOCK_STORAGE_KEY, JSON.stringify(envelope))
    } catch {
      /* see saveMockEnvelope */
    }
  }
}

export function clearMockStorage(): void {
  if (!storageAvailable()) return
  if (writeTimer) {
    clearTimeout(writeTimer)
    writeTimer = null
  }
  window.localStorage.removeItem(MOCK_STORAGE_KEY)
}
