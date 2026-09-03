/**
 * useGlobalSettings — loads client.globalSettings, owns the editable draft,
 * the dirty flag, save/discard, and the workspace-store side effects:
 *
 * - Appearance edits live-preview through the ThemeEngine (workspace store).
 * - Save writes the whole draft via client.globalSettings.update, then applies
 *   appearance + sidebar/notification mirrors to the workspace store.
 * - Discard rolls the draft (and the live preview) back to the last saved
 *   settings.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type { GlobalSettings } from '@/client'
import { getClient } from '@/client'
import { useSessionStore } from '@/state'

import { applyAppearanceToWorkspace, applySavedSettingsToWorkspace, deepEqual, setPaths } from './model'

export interface GlobalSettingsController {
  /** Last saved settings (null while loading). */
  saved: GlobalSettings | null
  /** Editable draft (null while loading). */
  draft: GlobalSettings | null
  loading: boolean
  loadError: unknown
  /** Draft differs from saved. */
  dirty: boolean
  saving: boolean
  saveError: string | null
  set: (...entries: readonly (readonly [string, unknown])[]) => void
  save: () => Promise<void>
  discard: () => void
  retryLoad: () => void
  /** Replace both saved + draft (import / reset flows). */
  replaceAll: (next: GlobalSettings) => void
  clearSaveError: () => void
}

export function useGlobalSettings(): GlobalSettingsController {
  const [saved, setSaved] = useState<GlobalSettings | null>(null)
  const [draft, setDraft] = useState<GlobalSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<unknown>(null)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [nonce, setNonce] = useState(0)
  const pushToast = useSessionStore((s) => s.pushToast)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setLoadError(null)
    getClient()
      .globalSettings.get()
      .then((settings) => {
        if (cancelled) return
        setSaved(settings)
        setDraft(settings)
        setLoading(false)
      })
      .catch((err) => {
        if (cancelled) return
        setSaved(null)
        setDraft(null)
        setLoadError(err)
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [nonce])

  const dirty = useMemo(() => saved !== null && draft !== null && !deepEqual(saved, draft), [saved, draft])

  // Live preview: when the draft changes after load, push the appearance
  // slice into the workspace store so theme/density/font-scale apply now.
  const previewedRef = useRef<GlobalSettings | null>(null)
  useEffect(() => {
    if (!draft || previewedRef.current === draft) return
    previewedRef.current = draft
    applyAppearanceToWorkspace(draft)
  }, [draft])

  const set = useCallback(
    (...entries: readonly (readonly [string, unknown])[]) => {
      setDraft((current) => (current ? setPaths(current, entries) : current))
      setSaveError(null)
    },
    [],
  )

  const save = useCallback(async () => {
    const current = draft
    if (!current || saving) return
    setSaving(true)
    setSaveError(null)
    try {
      const result = await getClient().globalSettings.update(current)
      setSaved(result)
      setDraft(result)
      applySavedSettingsToWorkspace(result)
      pushToast({ kind: 'success', title: 'Settings saved' })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error'
      // Draft is preserved — the bar stays dirty and the user can retry.
      setSaveError(message)
    } finally {
      setSaving(false)
    }
  }, [draft, saving, pushToast])

  const discard = useCallback(() => {
    setDraft(saved)
    setSaveError(null)
    if (saved) applyAppearanceToWorkspace(saved)
  }, [saved])

  const retryLoad = useCallback(() => setNonce((n) => n + 1), [])

  const replaceAll = useCallback((next: GlobalSettings) => {
    setSaved(next)
    setDraft(next)
    setSaveError(null)
    applySavedSettingsToWorkspace(next)
  }, [])

  const clearSaveError = useCallback(() => setSaveError(null), [])

  return {
    saved,
    draft,
    loading,
    loadError,
    dirty,
    saving,
    saveError,
    set,
    save,
    discard,
    retryLoad,
    replaceAll,
    clearSaveError,
  }
}
