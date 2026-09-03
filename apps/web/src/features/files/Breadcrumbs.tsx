/**
 * Breadcrumbs (files.md §Canvas) — path segments as links under the tab bar:
 * mono 12 px, middle-truncated for deep paths, current file carries the dirty
 * dot + read-only lock. Directory segments reveal in the tree.
 */
import { CircleDot, Lock } from 'lucide-react'

import { Tooltip } from '@/components'
import { useFilesStore } from './filesStore'

export interface BreadcrumbsProps {
  instanceId: string
  path: string
  onReveal: (path: string) => void
}

const MAX_SEGMENTS = 4

export function Breadcrumbs({ instanceId, path, onReveal }: BreadcrumbsProps) {
  const doc = useFilesStore((s) => s.docs[instanceId]?.[path])
  const dirty = doc ? doc.status === 'ready' && doc.draft !== doc.savedContent : false
  const segments = path.split('/')

  let visible: { label: string; path: string; isFile: boolean }[] = segments.map((label, i) => ({
    label,
    path: segments.slice(0, i + 1).join('/'),
    isFile: i === segments.length - 1,
  }))
  let truncated = false
  if (visible.length > MAX_SEGMENTS) {
    visible = [visible[0], ...visible.slice(-(MAX_SEGMENTS - 1))]
    truncated = true
  }

  return (
    <nav aria-label="File path" className="flex h-6 shrink-0 items-center gap-1 border-b border-border bg-surface px-3" data-testid="breadcrumbs">
      {visible.map((segment, i) => (
        <span key={segment.path} className="flex min-w-0 items-center gap-1">
          {i > 0 ? (
            <span aria-hidden="true" className="text-xs text-foreground-tertiary">
              /
            </span>
          ) : null}
          {truncated && i === 1 ? (
            <>
              <Tooltip content={path}>
                <span className="font-mono text-xs text-foreground-tertiary" aria-hidden="true">
                  …
                </span>
              </Tooltip>
              <span aria-hidden="true" className="text-xs text-foreground-tertiary">
                /
              </span>
            </>
          ) : null}
          {segment.isFile ? (
            <span className="flex min-w-0 items-center gap-1 font-mono text-xs text-foreground" aria-current="page">
              <span className="truncate">{segment.label}</span>
              {dirty ? <CircleDot className="size-3 shrink-0 text-accent" aria-label="Unsaved changes" /> : null}
              {doc?.readOnly ? <Lock className="size-3 shrink-0 text-foreground-tertiary" aria-label="Read-only" /> : null}
            </span>
          ) : (
            <button
              type="button"
              onClick={() => onReveal(segment.path)}
              className="truncate rounded-xs font-mono text-xs text-foreground-secondary transition-colors duration-instant hover:text-foreground"
            >
              {segment.label}
            </button>
          )}
        </span>
      ))}
    </nav>
  )
}
