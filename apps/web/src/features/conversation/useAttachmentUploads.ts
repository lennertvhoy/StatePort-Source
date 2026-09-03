/**
 * useAttachmentUploads — composer's pending-attachment strip.
 *
 * Validates against the allowed types/limits before upload, simulates visible
 * progress while the client uploads, keeps failed uploads in place with an
 * honest error + Retry, and never touches the draft text. Only `ready`
 * attachments are taken on send; uploading/failed chips stay behind.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type { Attachment } from '@/client'
import { getClient } from '@/client'

import { checkAttachment } from './conversationModel'

export interface PendingFile {
  name: string
  mimeType: string
  sizeBytes: number
  contentBase64?: string
}

export interface AttachmentUploads {
  pending: Attachment[]
  /** True when at least one upload can be sent now. */
  hasReady: boolean
  /** True while any chip is mid-upload. */
  uploading: boolean
  addFiles(files: Iterable<PendingFile>): void
  retry(id: string): void
  /** False for validation rejections (nothing stored to re-upload). */
  canRetry(id: string): boolean
  remove(id: string): void
  /** Take (and clear) the ready attachments for a send. */
  takeReady(): Attachment[]
}

let localAttachmentSeq = 0
const PROGRESS_TICK_MS = 90
const PROGRESS_STEP = 9
const PROGRESS_CAP = 88

export function useAttachmentUploads(instanceId: string): AttachmentUploads {
  const [pending, setPending] = useState<Attachment[]>([])
  const filesRef = useRef(new Map<string, PendingFile>())
  const timersRef = useRef(new Map<string, ReturnType<typeof setInterval>>())
  const storedIdsRef = useRef(new Set<string>())
  const deletingIdsRef = useRef(new Set<string>())

  // Fresh conversation → fresh strip (state resets during render; the file
  // map — a ref — clears in an effect, the only place refs may be touched).
  const [prevInstance, setPrevInstance] = useState(instanceId)
  if (prevInstance !== instanceId) {
    setPrevInstance(instanceId)
    setPending([])
  }
  useEffect(() => {
    filesRef.current.clear()
    storedIdsRef.current.clear()
    deletingIdsRef.current.clear()
  }, [instanceId])

  // Clear all tickers on unmount.
  useEffect(() => {
    const timers = timersRef.current
    return () => {
      for (const t of timers.values()) clearInterval(t)
      timers.clear()
    }
  }, [])

  const stopTicker = useCallback((id: string) => {
    const timer = timersRef.current.get(id)
    if (timer) clearInterval(timer)
    timersRef.current.delete(id)
  }, [])

  const startUpload = useCallback(
    (localId: string, file: PendingFile) => {
      stopTicker(localId)
      const timer = setInterval(() => {
        setPending((prev) =>
          prev.map((a) =>
            a.id === localId && a.state === 'uploading'
              ? { ...a, progress: Math.min(PROGRESS_CAP, (a.progress ?? 0) + PROGRESS_STEP) }
              : a,
          ),
        )
      }, PROGRESS_TICK_MS)
      timersRef.current.set(localId, timer)

      getClient()
        .conversation.uploadAttachment(instanceId, file)
        .then((result) => {
          stopTicker(localId)
          if (result.state === 'failed') {
            // Keep the local id stable so Retry re-uploads the same file.
            filesRef.current.set(localId, file)
            setPending((prev) => prev.map((a) => (a.id === localId ? { ...a, ...result, id: localId } : a)))
          } else {
            filesRef.current.delete(localId)
            storedIdsRef.current.add(result.id)
            setPending((prev) => prev.map((a) => (a.id === localId ? { ...result, progress: 100 } : a)))
          }
        })
        .catch(() => {
          stopTicker(localId)
          setPending((prev) =>
            prev.map((a) =>
              a.id === localId
                ? { ...a, state: 'failed' as const, error: 'Upload failed before completion. Nothing was stored — retry is safe.' }
                : a,
            ),
          )
        })
    },
    [instanceId, stopTicker],
  )

  const addFiles = useCallback(
    (files: Iterable<PendingFile>) => {
      for (const file of files) {
        localAttachmentSeq += 1
        const localId = `att_local_${Date.now().toString(36)}_${localAttachmentSeq}`
        const check = checkAttachment(file.name, file.mimeType, file.sizeBytes)
        if (!check.ok) {
          setPending((prev) => [
            ...prev,
            {
              id: localId,
              name: file.name,
              mimeType: file.mimeType,
              sizeBytes: file.sizeBytes,
              state: 'failed' as const,
              error: check.reason,
            },
          ])
          continue
        }
        filesRef.current.set(localId, file)
        setPending((prev) => [
          ...prev,
          {
            id: localId,
            name: file.name,
            mimeType: file.mimeType,
            sizeBytes: file.sizeBytes,
            state: 'uploading' as const,
            progress: 0,
          },
        ])
        startUpload(localId, file)
      }
    },
    [startUpload],
  )

  const retry = useCallback(
    (id: string) => {
      const file = filesRef.current.get(id)
      if (!file) {
        // Validation rejections have no stored file — removal is the recovery.
        return
      }
      setPending((prev) =>
        prev.map((a) => (a.id === id ? { ...a, state: 'uploading' as const, progress: 0, error: undefined } : a)),
      )
      startUpload(id, file)
    },
    [startUpload],
  )

  const remove = useCallback(
    (id: string) => {
      stopTicker(id)
      filesRef.current.delete(id)
      if (!storedIdsRef.current.has(id)) {
        setPending((prev) => prev.filter((a) => a.id !== id))
        return
      }
      if (deletingIdsRef.current.has(id)) return
      deletingIdsRef.current.add(id)
      void getClient()
        .conversation.deleteAttachment(instanceId, id)
        .then(() => {
          storedIdsRef.current.delete(id)
          setPending((prev) => prev.filter((a) => a.id !== id))
        })
        .catch(() => {
          setPending((prev) =>
            prev.map((attachment) =>
              attachment.id === id
                ? {
                    ...attachment,
                    state: 'failed' as const,
                    error:
                      'Delete failed. The attachment remains stored; remove it again to retry.',
                  }
                : attachment,
            ),
          )
        })
        .finally(() => {
          deletingIdsRef.current.delete(id)
        })
    },
    [instanceId, stopTicker],
  )

  const canRetry = useCallback((id: string) => filesRef.current.has(id), [])

  const takeReady = useCallback(() => {
    const ready = pending.filter((a) => a.state === 'ready')
    if (ready.length > 0) {
      setPending((prev) => prev.filter((a) => a.state !== 'ready'))
    }
    return ready
  }, [pending])

  return useMemo(
    () => ({
      pending,
      hasReady: pending.some((a) => a.state === 'ready'),
      uploading: pending.some((a) => a.state === 'uploading'),
      addFiles,
      retry,
      canRetry,
      remove,
      takeReady,
    }),
    [pending, addFiles, retry, canRetry, remove, takeReady],
  )
}
