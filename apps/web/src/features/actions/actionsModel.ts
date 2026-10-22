/**
 * Pure rules for the application actions card (ADR-0007 actions: `check` and
 * `agent`). Engine choice never leaves the action's declared allow-list,
 * inputs are validated against the action's own schema before anything is
 * prepared, and a run's outcome is read only from its recorded status.
 */
import type { ExecutionEngine, GovernedAction, RunRecord, RunStatus } from '@/client'
import { checkVerdictOf, fileProposalOf, runFailureReason, type EvaluatorResult, type FileProposalView } from '@/client/proposals'
import { enginesForAction, schemaInputFields } from '@/features/runs/runsModel'

export type ActionKind = 'check' | 'agent'
export type KindedAction = GovernedAction & { kind: ActionKind }

export function isSetupAction(actionId: string): boolean {
  return actionId.includes('setup-')
}

/** A setup action counts as run once one of its runs closed successfully. */
function setupRunSucceeded(run: RunRecord): boolean {
  return (
    run.status === 'applied'
    || run.status === 'completed'
    || (run.status === 'result_validating' && run.lifecycleState === 'CLOSED')
  )
}

export function setupPending(actions: KindedAction[], history: RunRecord[]): boolean {
  if (!actions.some((action) => isSetupAction(action.id))) return false
  return !history.some((run) => isSetupAction(run.actionId) && setupRunSucceeded(run))
}

/**
 * The actions the card offers: `check` and `agent` only (older typed actions
 * stay on the Runs page). While setup has never run, setup actions come first.
 */
export function cardActions(actions: GovernedAction[], history: RunRecord[]): { actions: KindedAction[]; setupFirst: boolean } {
  const kinded = actions.filter((action): action is KindedAction => action.kind === 'check' || action.kind === 'agent')
  const setupFirst = setupPending(kinded, history)
  if (!setupFirst) return { actions: kinded, setupFirst }
  return {
    actions: [...kinded.filter((action) => isSetupAction(action.id)), ...kinded.filter((action) => !isSetupAction(action.id))],
    setupFirst,
  }
}

const AGENT_ENGINE_PREFERENCE = ['opencode']

/**
 * The engine to prepare with: the first available engine in the action's
 * declared allow-list; with no allow-list, agent actions use OpenCode and
 * checks the first available engine. `undefined` means none can run it.
 */
export function engineForAction(action: KindedAction, engines: ExecutionEngine[]): ExecutionEngine | undefined {
  const available = enginesForAction(action, engines).filter((engine) => engine.availability === 'available')
  if (action.engineIds.length > 0) return available[0]
  if (action.kind === 'agent') {
    return AGENT_ENGINE_PREFERENCE.map((id) => available.find((engine) => engine.id === id)).find(Boolean)
  }
  return available[0]
}

// ── Inputs (generated from the action's inputSchema) ────────────────────────

export interface ActionInputField {
  name: string
  label: string
  /** 'string' | 'integer' | 'number' | 'boolean' | 'date' | 'text' (long string). */
  type: 'string' | 'text' | 'integer' | 'number' | 'boolean' | 'date'
  required: boolean
  description?: string
  maxLength?: number
  minimum?: number
  maximum?: number
  enumValues?: string[]
  defaultValue?: string | boolean
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined
}

const LONG_TEXT = 200

/**
 * A label from a property name when the schema declares no title:
 * `firstSlice` → "First slice", `hours_per_week` → "Hours per week".
 */
export function humanizeFieldName(name: string): string {
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .trim()
    .toLowerCase()
  return words.replace(/^./, (letter) => letter.toUpperCase())
}

export function actionInputFields(action: GovernedAction): ActionInputField[] {
  const properties = record(action.inputSchema?.properties) ?? {}
  return schemaInputFields(action.inputSchema).map((field) => {
    const raw = record(properties[field.name]) ?? {}
    const maxLength = typeof raw.maxLength === 'number' && raw.maxLength > 0 ? raw.maxLength : undefined
    const format = typeof raw.format === 'string' ? raw.format : undefined
    const type: ActionInputField['type'] =
      field.type === 'integer' || field.type === 'number' || field.type === 'boolean'
        ? field.type
        : format === 'date'
          ? 'date'
          : maxLength === undefined || maxLength > LONG_TEXT
            ? 'text'
            : 'string'
    const defaultValue =
      typeof field.defaultValue === 'boolean' || typeof field.defaultValue === 'string'
        ? field.defaultValue
        : typeof field.defaultValue === 'number'
          ? String(field.defaultValue)
          : undefined
    const hasTitle = typeof raw.title === 'string' && raw.title.trim().length > 0
    return {
      name: field.name,
      label: hasTitle ? field.label : humanizeFieldName(field.name),
      type,
      required: field.required,
      description: field.description,
      maxLength,
      minimum: typeof raw.minimum === 'number' ? raw.minimum : undefined,
      maximum: typeof raw.maximum === 'number' ? raw.maximum : undefined,
      enumValues: field.enumValues?.map(String),
      defaultValue,
    }
  })
}

export type ActionInputValues = Record<string, string | boolean>

export function initialInputValues(fields: ActionInputField[]): ActionInputValues {
  return Object.fromEntries(
    fields.map((field) => [field.name, field.type === 'boolean' ? Boolean(field.defaultValue) : (field.defaultValue as string | undefined) ?? '']),
  )
}

export type ParsedInputs =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; errors: Record<string, string> }

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/

/** Validate the form against the schema: required, maxLength, integer/number bounds, dates, enums. */
export function parseActionInputs(fields: ActionInputField[], values: ActionInputValues): ParsedInputs {
  const errors: Record<string, string> = {}
  const value: Record<string, unknown> = {}
  for (const field of fields) {
    const raw = values[field.name]
    if (field.type === 'boolean') {
      value[field.name] = Boolean(raw)
      continue
    }
    const text = typeof raw === 'string' ? raw.trim() : ''
    if (!text) {
      if (field.required) errors[field.name] = `${field.label} is required.`
      continue
    }
    if (field.maxLength !== undefined && text.length > field.maxLength) {
      errors[field.name] = `${field.label} can be at most ${field.maxLength} characters.`
      continue
    }
    if (field.enumValues && !field.enumValues.includes(text)) {
      errors[field.name] = `${field.label} must be one of the listed values.`
      continue
    }
    if (field.type === 'integer' || field.type === 'number') {
      const number = Number(text)
      if (!Number.isFinite(number) || (field.type === 'integer' && !Number.isInteger(number))) {
        errors[field.name] = `${field.label} must be ${field.type === 'integer' ? 'a whole number' : 'a number'}.`
        continue
      }
      if (field.minimum !== undefined && number < field.minimum) {
        errors[field.name] = `${field.label} must be at least ${field.minimum}.`
        continue
      }
      if (field.maximum !== undefined && number > field.maximum) {
        errors[field.name] = `${field.label} must be at most ${field.maximum}.`
        continue
      }
      value[field.name] = number
      continue
    }
    if (field.type === 'date' && (!ISO_DATE.test(text) || Number.isNaN(Date.parse(text)))) {
      errors[field.name] = `${field.label} must be a date (YYYY-MM-DD).`
      continue
    }
    value[field.name] = text
  }
  return Object.keys(errors).length > 0 ? { ok: false, errors } : { ok: true, value }
}

/** "Label: value" lines for the confirmation, in schema order, omitting empty optionals. */
export function inputSummary(fields: ActionInputField[], inputs: Record<string, unknown>): Array<{ label: string; value: string }> {
  return fields
    .filter((field) => inputs[field.name] !== undefined)
    .map((field) => {
      const raw = inputs[field.name]
      return { label: field.label, value: typeof raw === 'boolean' ? (raw ? 'Yes' : 'No') : String(raw) }
    })
}

// ── Run lifecycle and outcomes ──────────────────────────────────────────────

/** Statuses during which a run is still working (the card keeps waiting). */
export const IN_FLIGHT_STATUSES: ReadonlySet<RunStatus> = new Set<RunStatus>([
  'requested',
  'planned',
  'preparing',
  'prepared',
  'running',
  'awaiting_tool_approval',
  'cancelling',
  'applying',
])

export function runSettled(run: RunRecord): boolean {
  return !run.status || !IN_FLIGHT_STATUSES.has(run.status)
}

/** Most recently updated run per action id. */
export function latestRunByAction(history: RunRecord[]): Map<string, RunRecord> {
  const latest = new Map<string, RunRecord>()
  for (const run of history) {
    const current = latest.get(run.actionId)
    if (!current || run.updatedAt.localeCompare(current.updatedAt) > 0) latest.set(run.actionId, run)
  }
  return latest
}

const FAILED_STATUSES: ReadonlySet<RunStatus> = new Set<RunStatus>([
  'failed',
  'timed_out',
  'result_rejected',
  'apply_failed',
  'cancelled',
  'interrupted',
])

export type CheckOutcome =
  | { kind: 'verdict'; result: EvaluatorResult; at: string }
  | { kind: 'failed'; reason: string; at: string }
  | { kind: 'unrecorded'; at: string }
  | { kind: 'pending' }

export function checkOutcomeOf(run: RunRecord): CheckOutcome {
  if (!runSettled(run) || run.status === 'awaiting_approval' || run.status === 'approved') return { kind: 'pending' }
  if (run.status && FAILED_STATUSES.has(run.status)) {
    return { kind: 'failed', reason: runFailureReason(run) ?? 'The check did not finish.', at: run.updatedAt }
  }
  const result = checkVerdictOf(run)
  return result ? { kind: 'verdict', result, at: run.updatedAt } : { kind: 'unrecorded', at: run.updatedAt }
}

export type AgentOutcome =
  | { kind: 'proposal'; proposal: FileProposalView; run: RunRecord }
  | { kind: 'other_proposal'; run: RunRecord }
  | { kind: 'no_change'; summary: string | null; at: string }
  | { kind: 'failed'; reason: string; at: string }
  | { kind: 'pending' }

const PROPOSAL_STATUSES: ReadonlySet<RunStatus> = new Set<RunStatus>([
  'state_change_proposed',
  'state_change_approved',
  'state_change_rejected',
  'applying',
  'applied',
  'apply_failed',
])

export function agentOutcomeOf(run: RunRecord): AgentOutcome {
  if (run.status && PROPOSAL_STATUSES.has(run.status)) {
    const proposal = fileProposalOf(run)
    return proposal ? { kind: 'proposal', proposal, run } : { kind: 'other_proposal', run }
  }
  if (!runSettled(run) || run.status === 'awaiting_approval' || run.status === 'approved') return { kind: 'pending' }
  if (run.status && FAILED_STATUSES.has(run.status)) {
    return { kind: 'failed', reason: runFailureReason(run) ?? 'The agent run did not finish.', at: run.updatedAt }
  }
  const summary = typeof run.result?.summary === 'string' ? run.result.summary : null
  return { kind: 'no_change', summary, at: run.updatedAt }
}

export type ActionPhase = 'preparing' | 'approving' | 'running' | 'applying' | 'rejecting'

export function phaseLabel(phase: ActionPhase, kind: ActionKind): string {
  switch (phase) {
    case 'preparing':
      return 'Preparing the run'
    case 'approving':
      return 'Recording your approval'
    case 'running':
      return kind === 'agent' ? 'The agent is working on a copy' : 'Running the check'
    case 'applying':
      return 'Applying the change'
    case 'rejecting':
      return 'Discarding the proposal'
  }
}
