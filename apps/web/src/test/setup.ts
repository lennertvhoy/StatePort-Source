/**
 * Shared vitest setup. Keep this dependency-light: later agents may extend it,
 * but it must stay safe to run before any test file in a jsdom environment.
 */
import { afterEach, beforeEach } from 'vitest'

let localStorageAvailable = false
try {
  localStorageAvailable = typeof window !== 'undefined' && window.localStorage !== undefined
} catch {
  localStorageAvailable = false
}
if (typeof window !== 'undefined' && !localStorageAvailable) {
  const values = new Map<string, string>()
  const storage: Storage = {
    get length() { return values.size },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(key) },
    setItem: (key, value) => { values.set(key, String(value)) },
  }
  Object.defineProperty(window, 'localStorage', { configurable: true, value: storage })
}

beforeEach(() => {
  // Mock persistence is namespaced in localStorage — always start clean.
  window.localStorage.clear()
})

afterEach(() => {
  window.localStorage.clear()
})

// ── jsdom polyfills required by the shell (matchMedia / ResizeObserver / …) ──

if (typeof window !== 'undefined' && typeof window.matchMedia !== 'function') {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string): MediaQueryList => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }),
  })
}

if (typeof window !== 'undefined' && !('ResizeObserver' in window)) {
  class ResizeObserverStub {
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
  }
  Object.defineProperty(window, 'ResizeObserver', { writable: true, value: ResizeObserverStub })
}

if (typeof Element !== 'undefined') {
  if (!Element.prototype.scrollIntoView) {
    Element.prototype.scrollIntoView = () => undefined
  }
  if (!Element.prototype.hasPointerCapture) {
    Element.prototype.hasPointerCapture = () => false
    Element.prototype.setPointerCapture = () => undefined
    Element.prototype.releasePointerCapture = () => undefined
  }
}
