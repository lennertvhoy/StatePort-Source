/**
 * Workspace continuity — where "Continue" leads and what it restores
 * (applications.md §Section 1). Shared by the Applications home hero and the
 * App overview header; lives outside component modules so fast-refresh
 * boundaries stay component-only.
 */
import type { ApplicationInstance, WorkbenchToolId } from '@/client'
import { useWorkspaceStore } from '@/state'

const TOOL_LABELS: Record<WorkbenchToolId, string> = {
  overview: 'Overview',
  files: 'Files',
  terminal: 'Terminal',
  deployments: 'Deployments',
  orchestration: 'Orchestration',
  receipts: 'Receipts',
}

export interface ResumeTarget {
  route: string
  /** Human view label, e.g. "Files" or "Conversation". */
  viewLabel: string
  /** Additional restored context, e.g. "flake.nix · Terminal panel open". */
  contextLabel: string
}

/** Compute where Continue leads and what it restores (workspace store aware). */
export function resumeTargetFor(
  instance: ApplicationInstance,
  workspace: {
    lastInstanceId: string | null
    lastView: string | null
    lastWorkbenchTool: WorkbenchToolId | null
    layouts: Record<string, { bottomCollapsed?: boolean }>
    openFiles: Record<string, { path: string }[]>
    activeFile: Record<string, string | null>
  },
): ResumeTarget {
  const hasWorkbench = instance.capabilities.some(
    (c) => c.id === 'workbench' && (c.status === 'available' || c.status === 'degraded'),
  )
  const isLast = workspace.lastInstanceId === instance.id
  const view = isLast ? workspace.lastView : null
  const tool = isLast ? workspace.lastWorkbenchTool : null

  let route = `/app/${instance.id}`
  let viewLabel = 'Overview'
  if (view === 'conversation') {
    route = `/app/${instance.id}/conversation`
    viewLabel = 'Conversation'
  } else if (view === 'workbench' && hasWorkbench) {
    const toolSuffix = tool && tool !== 'overview' ? `/${tool}` : ''
    route = `/app/${instance.id}/workbench${toolSuffix}`
    viewLabel = tool ? TOOL_LABELS[tool] : 'Workbench'
  } else if (view === 'settings') {
    route = `/app/${instance.id}/settings`
    viewLabel = 'Settings'
  }

  // Workspace context line: what the user will find restored.
  const parts: string[] = []
  if (hasWorkbench) {
    const activeFile = workspace.activeFile[instance.id]
    if (activeFile) parts.push(activeFile.split('/').pop() ?? activeFile)
    else {
      const open = workspace.openFiles[instance.id] ?? []
      if (open.length > 0) parts.push(`${open.length} ${open.length === 1 ? 'file' : 'files'} open`)
    }
    const layout = workspace.layouts[instance.id]
    if (layout && layout.bottomCollapsed === false) parts.push('Terminal panel open')
  }
  return { route, viewLabel, contextLabel: parts.join(' · ') }
}

/** Read the workspace store once for the hero (hook wrapper for convenience). */
export function useWorkspaceContinuity() {
  const lastInstanceId = useWorkspaceStore((s) => s.lastInstanceId)
  const lastView = useWorkspaceStore((s) => s.lastView)
  const lastWorkbenchTool = useWorkspaceStore((s) => s.lastWorkbenchTool)
  const layouts = useWorkspaceStore((s) => s.layouts)
  const openFiles = useWorkspaceStore((s) => s.openFiles)
  const activeFile = useWorkspaceStore((s) => s.activeFile)
  return { lastInstanceId, lastView, lastWorkbenchTool, layouts, openFiles, activeFile }
}
