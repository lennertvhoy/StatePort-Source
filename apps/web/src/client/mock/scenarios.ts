/**
 * Scenario Lab engine (dev-only; never in production navigation).
 *
 * - Registry of every scenario from the brief's "Scenario Lab" section.
 * - The active scenario is read from the `?scenario=` query param and held in
 *   a zustand dev store so the Scenario Lab panel can switch at runtime.
 * - Scenarios override mock *behavior* (latency, failures, read-time views);
 *   they never edit seed data. The mock adapter interprets `behavior`.
 */
import { create } from 'zustand'

import type { LocalServiceState } from '../types'

// ─────────────────────────────────────────────────────────────────────────────
// Behavior model — what the mock adapter reads before every call
// ─────────────────────────────────────────────────────────────────────────────

export interface ScenarioBehavior {
  /** Multiply simulated latency (slow service). */
  latencyMultiplier?: number
  /** Force the local-service read model. */
  serviceState?: LocalServiceState
  /** Fail every request with a transport error. */
  failRequests?: { status: number; message: string }
  /** applications.list() returns []. */
  hideApplications?: boolean
  /** Every instance reports degraded health. */
  degradeInstances?: boolean
  approvals?: 'empty' | 'pending' | 'stale'
  conversation?: 'loading' | 'empty' | 'active' | 'streaming' | 'failed'
  attachmentUploadFails?: boolean
  files?: 'empty' | 'populated' | 'dirty' | 'read_only' | 'write_failed'
  terminal?: 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'failed'
  targetUnavailable?: boolean
  vm?: 'stopped' | 'running_unchecked' | 'healthy'
  repoDirty?: boolean
  infraPlan?: 'prepared' | 'awaiting_approval' | 'running' | 'failed'
  orchestration?: 'unavailable' | 'backend_unavailable' | 'proposal_ready' | 'approved' | 'running' | 'awaiting_review' | 'closed'
  receipts?: 'empty' | 'populated'
  backupDue?: boolean
  authorization?: 'proposed' | 'active'
}

export type ScenarioId =
  | 'service_connected'
  | 'service_offline'
  | 'service_slow'
  | 'request_failure'
  | 'no_applications'
  | 'application_ready'
  | 'application_degraded'
  | 'approvals_empty'
  | 'approval_pending'
  | 'approval_stale'
  | 'conversation_loading'
  | 'conversation_empty'
  | 'conversation_active'
  | 'conversation_streaming'
  | 'conversation_failed'
  | 'attachment_upload_failed'
  | 'files_empty'
  | 'files_populated'
  | 'file_dirty'
  | 'file_read_only'
  | 'file_write_failed'
  | 'terminal_idle'
  | 'terminal_connecting'
  | 'terminal_connected'
  | 'terminal_reconnecting'
  | 'terminal_failed'
  | 'deployment_target_unavailable'
  | 'vm_stopped'
  | 'vm_running_unchecked'
  | 'vm_healthy'
  | 'repo_dirty'
  | 'infra_plan_prepared'
  | 'infra_awaiting_approval'
  | 'infra_running'
  | 'infra_failed'
  | 'orchestration_unavailable'
  | 'orchestration_backend_unavailable'
  | 'orchestration_proposal_ready'
  | 'orchestration_approved'
  | 'orchestration_running'
  | 'orchestration_awaiting_review'
  | 'orchestration_closed'
  | 'receipts_empty'
  | 'receipts_populated'
  | 'backup_due'
  | 'authorization_proposed'
  | 'authorization_active'

export interface ScenarioDefinition {
  id: ScenarioId
  label: string
  group: string
  behavior: ScenarioBehavior
}

export const SCENARIO_GROUPS = [
  'Service',
  'Applications',
  'Approvals',
  'Conversation',
  'Files',
  'Terminal',
  'Infrastructure',
  'Orchestration',
  'Receipts & recovery',
  'Authorization',
] as const

export const SCENARIOS = [
  // Service
  { id: 'service_connected', label: 'Service connected', group: 'Service', behavior: { serviceState: 'connected' } },
  { id: 'service_offline', label: 'Service offline', group: 'Service', behavior: { serviceState: 'offline' } },
  { id: 'service_slow', label: 'Slow service', group: 'Service', behavior: { latencyMultiplier: 6 } },
  { id: 'request_failure', label: 'Request failure', group: 'Service', behavior: { failRequests: { status: 500, message: 'Simulated request failure' } } },
  // Applications
  { id: 'no_applications', label: 'No applications', group: 'Applications', behavior: { hideApplications: true } },
  { id: 'application_ready', label: 'Application ready', group: 'Applications', behavior: {} },
  { id: 'application_degraded', label: 'Application degraded', group: 'Applications', behavior: { degradeInstances: true } },
  // Approvals
  { id: 'approvals_empty', label: 'Empty approvals', group: 'Approvals', behavior: { approvals: 'empty' } },
  { id: 'approval_pending', label: 'Pending approval', group: 'Approvals', behavior: { approvals: 'pending' } },
  { id: 'approval_stale', label: 'Stale approval', group: 'Approvals', behavior: { approvals: 'stale' } },
  // Conversation
  { id: 'conversation_loading', label: 'Conversation loading', group: 'Conversation', behavior: { conversation: 'loading' } },
  { id: 'conversation_empty', label: 'Conversation empty', group: 'Conversation', behavior: { conversation: 'empty' } },
  { id: 'conversation_active', label: 'Conversation active', group: 'Conversation', behavior: { conversation: 'active' } },
  { id: 'conversation_streaming', label: 'Conversation streaming', group: 'Conversation', behavior: { conversation: 'streaming' } },
  { id: 'conversation_failed', label: 'Conversation failed', group: 'Conversation', behavior: { conversation: 'failed' } },
  { id: 'attachment_upload_failed', label: 'Attachment upload failed', group: 'Conversation', behavior: { attachmentUploadFails: true } },
  // Files
  { id: 'files_empty', label: 'Files empty', group: 'Files', behavior: { files: 'empty' } },
  { id: 'files_populated', label: 'Files populated', group: 'Files', behavior: { files: 'populated' } },
  { id: 'file_dirty', label: 'File dirty', group: 'Files', behavior: { files: 'dirty' } },
  { id: 'file_read_only', label: 'File read-only', group: 'Files', behavior: { files: 'read_only' } },
  { id: 'file_write_failed', label: 'File write failed', group: 'Files', behavior: { files: 'write_failed' } },
  // Terminal
  { id: 'terminal_idle', label: 'Terminal idle', group: 'Terminal', behavior: { terminal: 'idle' } },
  { id: 'terminal_connecting', label: 'Terminal connecting', group: 'Terminal', behavior: { terminal: 'connecting' } },
  { id: 'terminal_connected', label: 'Terminal connected', group: 'Terminal', behavior: { terminal: 'connected' } },
  { id: 'terminal_reconnecting', label: 'Terminal reconnecting', group: 'Terminal', behavior: { terminal: 'reconnecting' } },
  { id: 'terminal_failed', label: 'Terminal failed', group: 'Terminal', behavior: { terminal: 'failed' } },
  // Infrastructure
  { id: 'deployment_target_unavailable', label: 'Deployment target unavailable', group: 'Infrastructure', behavior: { targetUnavailable: true } },
  { id: 'vm_stopped', label: 'VM stopped', group: 'Infrastructure', behavior: { vm: 'stopped' } },
  { id: 'vm_running_unchecked', label: 'VM running, health unchecked', group: 'Infrastructure', behavior: { vm: 'running_unchecked' } },
  { id: 'vm_healthy', label: 'VM healthy', group: 'Infrastructure', behavior: { vm: 'healthy' } },
  { id: 'repo_dirty', label: 'Repository dirty', group: 'Infrastructure', behavior: { repoDirty: true } },
  { id: 'infra_plan_prepared', label: 'Infrastructure plan prepared', group: 'Infrastructure', behavior: { infraPlan: 'prepared' } },
  { id: 'infra_awaiting_approval', label: 'Infrastructure awaiting approval', group: 'Infrastructure', behavior: { infraPlan: 'awaiting_approval' } },
  { id: 'infra_running', label: 'Infrastructure running', group: 'Infrastructure', behavior: { infraPlan: 'running' } },
  { id: 'infra_failed', label: 'Infrastructure failed', group: 'Infrastructure', behavior: { infraPlan: 'failed' } },
  // Orchestration
  { id: 'orchestration_unavailable', label: 'Orchestration unavailable', group: 'Orchestration', behavior: { orchestration: 'unavailable' } },
  { id: 'orchestration_backend_unavailable', label: 'Orchestration backend unavailable', group: 'Orchestration', behavior: { orchestration: 'backend_unavailable' } },
  { id: 'orchestration_proposal_ready', label: 'Orchestration proposal ready', group: 'Orchestration', behavior: { orchestration: 'proposal_ready' } },
  { id: 'orchestration_approved', label: 'Orchestration approved', group: 'Orchestration', behavior: { orchestration: 'approved' } },
  { id: 'orchestration_running', label: 'Orchestration running', group: 'Orchestration', behavior: { orchestration: 'running' } },
  { id: 'orchestration_awaiting_review', label: 'Orchestration awaiting review', group: 'Orchestration', behavior: { orchestration: 'awaiting_review' } },
  { id: 'orchestration_closed', label: 'Orchestration closed', group: 'Orchestration', behavior: { orchestration: 'closed' } },
  // Receipts & recovery
  { id: 'receipts_empty', label: 'Receipts empty', group: 'Receipts & recovery', behavior: { receipts: 'empty' } },
  { id: 'receipts_populated', label: 'Receipts populated', group: 'Receipts & recovery', behavior: { receipts: 'populated' } },
  { id: 'backup_due', label: 'Backup due', group: 'Receipts & recovery', behavior: { backupDue: true } },
  // Authorization
  { id: 'authorization_proposed', label: 'Local authorization proposed', group: 'Authorization', behavior: { authorization: 'proposed' } },
  { id: 'authorization_active', label: 'Local authorization active', group: 'Authorization', behavior: { authorization: 'active' } },
] as const satisfies readonly ScenarioDefinition[]

const registry = new Map<ScenarioId, ScenarioDefinition>(
  (SCENARIOS as readonly ScenarioDefinition[]).map((s) => [s.id, s]),
)

export function getScenarioDefinition(id: ScenarioId): ScenarioDefinition {
  const def = registry.get(id)
  if (!def) throw new Error(`Unknown scenario: ${id}`)
  return def
}

export function isScenarioId(value: string): value is ScenarioId {
  return registry.has(value as ScenarioId)
}

// ─────────────────────────────────────────────────────────────────────────────
// Active scenario — `?scenario=` param + zustand dev store
// ─────────────────────────────────────────────────────────────────────────────

/** `?scenario=lab` opens the Scenario Lab panel without activating a scenario. */
export const SCENARIO_LAB_PARAM = 'lab'

function readScenarioParam(): { scenario: ScenarioId | null; labOpen: boolean } {
  if (typeof window === 'undefined') return { scenario: null, labOpen: false }
  const value = new URLSearchParams(window.location.search).get('scenario')
  if (!value) return { scenario: null, labOpen: false }
  if (value === SCENARIO_LAB_PARAM) return { scenario: null, labOpen: true }
  if (isScenarioId(value)) return { scenario: value, labOpen: false }
  return { scenario: null, labOpen: false }
}

function writeScenarioParam(id: ScenarioId | null, labOpen: boolean): void {
  if (typeof window === 'undefined') return
  const params = new URLSearchParams(window.location.search)
  params.delete('scenario')
  if (id) params.set('scenario', id)
  else if (labOpen) params.set('scenario', SCENARIO_LAB_PARAM)
  const query = params.toString()
  const url = `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash}`
  window.history.replaceState(null, '', url)
}

interface ScenarioStoreState {
  active: ScenarioId | null
  labOpen: boolean
  setActive: (id: ScenarioId | null) => void
  setLabOpen: (open: boolean) => void
}

export const useScenarioStore = create<ScenarioStoreState>((set) => {
  const initial = readScenarioParam()
  return {
    active: initial.scenario,
    labOpen: initial.labOpen,
    setActive: (id) => {
      const labOpen = id ? false : useScenarioStore.getState().labOpen
      set({ active: id, labOpen })
      writeScenarioParam(id, labOpen)
    },
    setLabOpen: (open) => {
      set({ labOpen: open })
      writeScenarioParam(useScenarioStore.getState().active, open)
    },
  }
})

/** Non-reactive accessor for the mock adapter (reads before every call). */
export function getActiveScenario(): ScenarioId | null {
  return useScenarioStore.getState().active
}

export function getActiveBehavior(): ScenarioBehavior | null {
  const id = getActiveScenario()
  return id ? getScenarioDefinition(id).behavior : null
}
