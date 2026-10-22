/**
 * Workspace continuity — where "Continue" leads and what it restores
 * (applications.md §Section 1). Shared by the Applications home hero and the
 * App overview header; lives outside component modules so fast-refresh
 * boundaries stay component-only.
 */
import type { ApplicationInstance } from '@/client'
import { useWorkspaceStore } from '@/state'

export interface ResumeTarget {
  route: string
  /** Human view label, e.g. "Conversation". */
  viewLabel: string
}

export interface ResumePreferences {
  /** When false, land on the application overview instead of its saved view. */
  restoreLastApplicationView?: boolean
}

/** Compute where Continue leads and what it restores (workspace store aware). */
export function resumeTargetFor(
  instance: ApplicationInstance,
  workspace: {
    lastInstanceId: string | null
    lastView: string | null
  },
  preferences: ResumePreferences = {},
): ResumeTarget {
  const isLast = workspace.lastInstanceId === instance.id
  const view = isLast && preferences.restoreLastApplicationView !== false ? workspace.lastView : null

  let route = `/app/${instance.id}`
  let viewLabel = 'Overview'
  if (view === 'conversation') {
    route = `/app/${instance.id}/conversation`
    viewLabel = 'Conversation'
  } else if (view === 'settings') {
    route = `/app/${instance.id}/settings`
    viewLabel = 'Settings'
  }

  return { route, viewLabel }
}

/** Read the workspace store once for the hero (hook wrapper for convenience). */
export function useWorkspaceContinuity() {
  const lastInstanceId = useWorkspaceStore((s) => s.lastInstanceId)
  const lastView = useWorkspaceStore((s) => s.lastView)
  return { lastInstanceId, lastView }
}
