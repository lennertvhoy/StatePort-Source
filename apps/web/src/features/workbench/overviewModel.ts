/**
 * Workbench Overview model — pure helpers for the workbench's operational
 * summary (workbench.md §"Workbench Overview tool"): tool rows with honest
 * one-line statuses, preset labels, and layout patch semantics that mirror
 * the shell's preset application (the shell's own map is not exported, so
 * the collapse semantics are restated here from design.md §10.2).
 */
import { FolderTree, Receipt, Server, SquareTerminal, Workflow } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import type {
  CapabilityId,
  InfrastructureTarget,
  OrchestrationSession,
  TerminalSession,
  WorkbenchToolId,
} from '@/client'
import { terminalStatePresentation, vmStatePresentation } from '@/semantic'
import type { SemanticPresentation } from '@/semantic'
import type { AppLayout, LayoutPreset } from '@/state'

// ─────────────────────────────────────────────────────────────────────────────
// Tool links (capability-filtered; unavailable tools are omitted, never ghosts)
// ─────────────────────────────────────────────────────────────────────────────

export interface OverviewToolLink {
  tool: WorkbenchToolId
  label: string
  icon: LucideIcon
  route: string
  capabilities: CapabilityId[]
}

export const OVERVIEW_TOOL_LINKS: readonly OverviewToolLink[] = [
  { tool: 'files', label: 'Files', icon: FolderTree, route: 'files', capabilities: ['file_viewer', 'editor'] },
  { tool: 'terminal', label: 'Terminal', icon: SquareTerminal, route: 'terminal', capabilities: ['terminal'] },
  { tool: 'deployments', label: 'Deployments', icon: Server, route: 'deployments', capabilities: ['infrastructure'] },
  { tool: 'orchestration', label: 'Orchestration', icon: Workflow, route: 'orchestration', capabilities: ['cto_orchestration'] },
  { tool: 'receipts', label: 'Receipts', icon: Receipt, route: 'receipts', capabilities: ['receipts'] },
]

// ─────────────────────────────────────────────────────────────────────────────
// Honest one-line tool statuses
// ─────────────────────────────────────────────────────────────────────────────

export interface ToolStatus {
  text: string
  presentation?: SemanticPresentation
}

export function filesToolStatus(openFileCount: number): ToolStatus {
  return openFileCount > 0
    ? { text: `${openFileCount} file${openFileCount === 1 ? '' : 's'} open` }
    : { text: 'No files open' }
}

export function terminalToolStatus(session: TerminalSession | null | undefined): ToolStatus {
  if (!session) return { text: 'Ready to connect' }
  const presentation = terminalStatePresentation(session.state)
  return { text: presentation.label, presentation }
}

export function deploymentsToolStatus(target: InfrastructureTarget | null | undefined): ToolStatus {
  if (!target) return { text: 'State not checked' }
  const presentation = vmStatePresentation(target.vm.state)
  return { text: `VM ${presentation.label.toLowerCase()}`, presentation }
}

export function orchestrationToolStatus(session: OrchestrationSession | null | undefined): ToolStatus {
  if (!session) return { text: 'No active session' }
  return { text: session.objective ? `In progress — ${session.objective}` : 'Session in progress' }
}

export function receiptsToolStatus(count: number): ToolStatus {
  return count === 0 ? { text: 'No receipts yet' } : { text: `${count} receipt${count === 1 ? '' : 's'}` }
}

// ─────────────────────────────────────────────────────────────────────────────
// Layout presets (labels + collapse semantics, design.md §10.2)
// ─────────────────────────────────────────────────────────────────────────────

export const PRESET_LABELS: Record<LayoutPreset, string> = {
  focus: 'Focus',
  code: 'Code',
  code_terminal: 'Code + Terminal',
  conversation_files: 'Conversation + Files',
  conversation_terminal: 'Conversation + Terminal',
  infrastructure: 'Infrastructure',
  review: 'Review',
}

export const PRESET_ORDER: readonly LayoutPreset[] = [
  'focus',
  'code',
  'code_terminal',
  'conversation_files',
  'conversation_terminal',
  'infrastructure',
  'review',
]

/** Collapse flags per preset — mirrors WorkbenchShell's preset application. */
export function presetLayoutPatch(preset: LayoutPreset): Partial<AppLayout> {
  switch (preset) {
    case 'focus':
      return { preset, navCollapsed: true, rightDockCollapsed: true, bottomCollapsed: true }
    case 'code':
      return { preset, navCollapsed: false, rightDockCollapsed: true, bottomCollapsed: true }
    case 'code_terminal':
      return { preset, navCollapsed: false, rightDockCollapsed: true, bottomCollapsed: false }
    case 'conversation_files':
      return { preset, navCollapsed: false, rightDockCollapsed: false, bottomCollapsed: true }
    case 'conversation_terminal':
      return { preset, navCollapsed: false, rightDockCollapsed: false, bottomCollapsed: false }
    case 'infrastructure':
      return { preset, navCollapsed: false, rightDockCollapsed: true, bottomCollapsed: false }
    case 'review':
      return { preset, navCollapsed: true, rightDockCollapsed: false, bottomCollapsed: true }
  }
}

/** Capability display names for the capability list. */
export const CAPABILITY_LABELS: Partial<Record<CapabilityId, string>> = {
  conversation: 'Conversation',
  workbench: 'Workbench',
  file_viewer: 'File viewer',
  editor: 'Editor',
  terminal: 'Terminal',
  progress_dashboard: 'Progress dashboard',
  goal_execution: 'Goal execution',
  cto_orchestration: 'CTO orchestration',
  benchmark_evidence: 'Benchmark evidence',
  proactive_notifications: 'Proactive notifications',
  backup: 'Backup',
  infrastructure: 'Infrastructure',
  receipts: 'Receipts',
}
