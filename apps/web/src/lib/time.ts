/**
 * Small time formatting helpers shared by components. Lives outside component
 * modules so fast-refresh boundaries stay component-only.
 */

/** Format an elapsed duration as m:ss, switching to h mm' at the hour mark. */
export function formatElapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000))
  const minutes = Math.floor(total / 60)
  const seconds = total % 60
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60)
    return `${hours}h ${String(minutes % 60).padStart(2, '0')}m`
  }
  return `${minutes}:${String(seconds).padStart(2, '0')}`
}
