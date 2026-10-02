/**
 * Pure governed-runs presentation rules.
 *
 * Controls are derived only from the exact persisted run status. The coarser
 * `state` field is for semantic presentation and must never authorize a
 * transition: `approved` and `state_change_approved`, for example, have
 * different next operations even though both can present as approved.
 */
import type {
  ApplicationInstance,
  ExecutionEngine,
  GovernedAction,
  RunRecord,
  RunStatus,
} from '@/client'
import { applicationDestinationAvailable } from '@/features/application-experience/registry'

export function receiptBasePathFor(instance: ApplicationInstance): string | undefined {
  if (!applicationDestinationAvailable(instance, 'receipts')) return undefined
  return applicationDestinationAvailable(instance, 'workbench')
    ? `/app/${instance.id}/workbench/receipts`
    : `/app/${instance.id}/receipts`
}

export const CANCELLABLE_RUN_STATUSES: ReadonlySet<RunStatus> = new Set([
  'awaiting_approval',
  'approved',
  'prepared',
  'running',
  'cancelling',
  'interrupted',
])

export interface RunControls {
  approve: boolean
  execute: boolean
  proposalReview: boolean
  apply: boolean
  cancel: boolean
}

export function runControls(run: RunRecord): RunControls {
  const cancel = run.status ? CANCELLABLE_RUN_STATUSES.has(run.status) : false
  switch (run.status) {
    case 'awaiting_approval':
      return { approve: true, execute: false, proposalReview: false, apply: false, cancel }
    case 'approved':
      return { approve: false, execute: true, proposalReview: false, apply: false, cancel }
    case 'state_change_proposed':
      return { approve: false, execute: false, proposalReview: true, apply: false, cancel }
    case 'state_change_approved':
      return { approve: false, execute: false, proposalReview: false, apply: true, cancel }
    default:
      return { approve: false, execute: false, proposalReview: false, apply: false, cancel }
  }
}

export function isCancellable(run: RunRecord): boolean {
  return Boolean(run.status && CANCELLABLE_RUN_STATUSES.has(run.status))
}

/** A RunBundle may exist only after the execution attempt has reached evidence-bearing truth. */
export function canRequestRunEvidence(run: RunRecord): boolean {
  if (!run.status) return false
  // A non-CLOSED result_validating projection is only possible as a crash
  // artifact; only the closed record carries evidence-bearing truth.
  if (run.status === 'result_validating') return run.lifecycleState === 'CLOSED'
  return new Set<RunStatus>([
    'cancelled',
    'interrupted',
    'timed_out',
    'failed',
    'completed',
    'result_rejected',
    'state_change_proposed',
    'state_change_approved',
    'state_change_rejected',
    'apply_failed',
    'applied',
    'archived',
  ]).has(run.status)
}

export function runStatusLabel(status: RunStatus | undefined): string {
  if (!status) return 'Exact status unavailable'
  return status.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

/** Engines allowed by the action declaration. An empty declaration means all returned engines. */
export function enginesForAction(action: GovernedAction, engines: ExecutionEngine[]): ExecutionEngine[] {
  if (action.engineIds.length === 0) return engines
  return engines.filter((engine) => action.engineIds.includes(engine.id))
}

/** Never fall back to an engine outside the action's declared allow-list. */
export function defaultEngineFor(
  action: GovernedAction,
  engines: ExecutionEngine[],
): ExecutionEngine | undefined {
  return enginesForAction(action, engines).find((engine) => engine.availability === 'available')
}

export interface SchemaInputField {
  name: string
  label: string
  type: string
  required: boolean
  description?: string
  enumValues?: unknown[]
  defaultValue?: unknown
}

type JsonRecord = Record<string, unknown>

function record(value: unknown): JsonRecord | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined
}

export function schemaInputFields(schema: Record<string, unknown> | undefined): SchemaInputField[] {
  const properties = record(schema?.properties)
  if (!properties) return []
  const required = new Set(
    Array.isArray(schema?.required)
      ? schema.required.filter((item): item is string => typeof item === 'string')
      : [],
  )
  return Object.entries(properties).map(([name, rawDefinition]) => {
    const definition = record(rawDefinition) ?? {}
    const title = typeof definition.title === 'string' ? definition.title : undefined
    return {
      name,
      label: title ?? name.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase()),
      type: typeof definition.type === 'string' ? definition.type : 'string',
      required: required.has(name),
      description: typeof definition.description === 'string' ? definition.description : undefined,
      enumValues: Array.isArray(definition.enum) ? definition.enum : undefined,
      defaultValue: definition.default,
    }
  })
}

export type SchemaInputValues = Record<string, string | boolean>

export function defaultSchemaInputValues(
  schema: Record<string, unknown> | undefined,
): SchemaInputValues {
  return Object.fromEntries(
    schemaInputFields(schema).map((field) => [
      field.name,
      field.type === 'boolean'
        ? Boolean(field.defaultValue)
        : field.defaultValue === undefined
          ? ''
          : String(field.defaultValue),
    ]),
  )
}

export type ParseSchemaInputsResult =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; field?: string; error: string }

export function parseSchemaInputs(
  schema: Record<string, unknown> | undefined,
  values: SchemaInputValues,
): ParseSchemaInputsResult {
  const result: Record<string, unknown> = {}
  for (const field of schemaInputFields(schema)) {
    const raw = values[field.name]
    if (field.type === 'boolean') {
      result[field.name] = Boolean(raw)
      continue
    }
    const text = typeof raw === 'string' ? raw.trim() : ''
    if (!text) {
      if (field.required) {
        return { ok: false, field: field.name, error: `${field.label} is required.` }
      }
      continue
    }
    if (field.enumValues) {
      const match = field.enumValues.find((value) => String(value) === text)
      if (match === undefined) {
        return { ok: false, field: field.name, error: `${field.label} must use a declared value.` }
      }
      result[field.name] = match
      continue
    }
    if (field.type === 'number' || field.type === 'integer') {
      const number = Number(text)
      if (!Number.isFinite(number) || (field.type === 'integer' && !Number.isInteger(number))) {
        return {
          ok: false,
          field: field.name,
          error: `${field.label} must be ${field.type === 'integer' ? 'an integer' : 'a number'}.`,
        }
      }
      result[field.name] = number
      continue
    }
    if (field.type === 'object' || field.type === 'array') {
      try {
        const parsed: unknown = JSON.parse(text)
        const matchesType =
          field.type === 'array'
            ? Array.isArray(parsed)
            : typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
        if (!matchesType) throw new Error('wrong shape')
        result[field.name] = parsed
      } catch {
        return {
          ok: false,
          field: field.name,
          error: `${field.label} must be a valid JSON ${field.type}.`,
        }
      }
      continue
    }
    result[field.name] = text
  }
  return { ok: true, value: result }
}

/** Recursively withhold absolute host paths while retaining application-relative proposal paths. */
export function safeEvidenceValue(value: unknown): unknown {
  if (typeof value === 'string') {
    const absoluteUnix = value.startsWith('/') || value.startsWith('~/') || value.startsWith('file://')
    const absoluteWindows = /^[A-Za-z]:[\\/]/.test(value) || value.startsWith('\\\\')
    return absoluteUnix || absoluteWindows ? '[local path withheld]' : value
  }
  if (Array.isArray(value)) return value.map(safeEvidenceValue)
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, nested]) => [
        key,
        safeEvidenceValue(nested),
      ]),
    )
  }
  return value
}
