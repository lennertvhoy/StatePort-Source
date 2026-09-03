/** Public-safe, mock-only capture controls for the existing demo routes. */
export const STUDYSTATE_CAPTURE_PARAM = 'capture'
export const STUDYSTATE_CAPTURE_VALUE = 'studystate'
export const STUDYSTATE_CAPTURE_NOW = '2026-08-01T12:00:00.000Z'
export const STUDYSTATE_CAPTURE_NOW_MS = Date.parse(STUDYSTATE_CAPTURE_NOW)

export function isStudyStateCaptureRequested(): boolean {
  if (import.meta.env.VITE_STATEPORT_CAPTURE_MODE === STUDYSTATE_CAPTURE_VALUE) return true
  if (typeof window === 'undefined') return false
  return new URLSearchParams(window.location.search).get(STUDYSTATE_CAPTURE_PARAM) === STUDYSTATE_CAPTURE_VALUE
}
