/**
 * Shared vitest setup. Keep this dependency-light: later agents may extend it,
 * but it must stay safe to run before any test file in a jsdom environment.
 */
import { afterEach, beforeEach, vi } from 'vitest'

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

afterEach(async () => {
  window.localStorage.clear()
  // Radix FocusScope defers its unmount autofocus restore by one 0 ms tick
  // (@radix-ui/react-focus-scope index.mjs:90-92) and dispatches a CustomEvent
  // on the container it is tearing down. A test that unmounts a Dialog without
  // awaiting that tick leaves the timer pending; when the event loop is starved
  // long enough (a loaded parallel run), the timer outlives the jsdom
  // environment, `CustomEvent` then resolves to Node's class instead of jsdom's,
  // and jsdom rejects it with "parameter 1 is not of type 'Event'". Vitest
  // reports that as an unhandled error and exits non-zero even though every
  // test passed. Drain the tick here instead of in each test.
  //
  // This hook is registered before any test file's own afterEach, and vitest
  // runs afterEach hooks last-registered-first, so it always runs after the
  // `cleanup()` that queued the timer. Fake timers are left alone: they own
  // setTimeout, so the tick can never arrive and awaiting it would hang.
  if (!vi.isFakeTimers()) {
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
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
