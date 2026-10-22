/**
 * Wire schemas and mappers for the `/v1/models*` API (keep-up-loop.md "API").
 *
 * This file is the single integration point with the backend shape. It reads
 * the documented projection `stateport.models-projection/v1`
 * (`docs/API_CONTRACT_WEB.md` §"Model routes") field by field: an unknown or
 * missing member is a validation error, never a silently defaulted value.
 * Anything that would make the page claim more than the service said fails
 * closed.
 */
import { z } from 'zod'

import {
  FREE_DESTINATION,
  isFreeModelId,
  type CatalogueModel,
  type CatalogueResult,
  type ModelAlarm,
  type ModelCatalogue,
  type ModelConsent,
  type ModelLease,
  type ModelProbe,
  type ModelRoute,
  type ModelRouteRefusal,
  type ModelScore,
  type ModelsEvaluation,
  type ModelsReceipt,
  type ModelsSchedule,
  type ModelsStatus,
  type ModelsSuite,
  type ModelSuiteRun,
  type ModelsView,
  type RouteProposal,
  type SuiteModelResult,
  type SuiteRunState,
  type SuiteTaskResult,
} from '../models'
import { ClientError } from '../types'

function failClosed(what: string, detail?: string): never {
  throw new ClientError('validation', `Model routes projection failed closed: ${what}`, { detail })
}

function parseOrFail<T>(schema: z.ZodType<T>, value: unknown, what: string): T {
  const parsed = schema.safeParse(value)
  if (!parsed.success) {
    failClosed(
      what,
      parsed.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`).join('\n'),
    )
  }
  return parsed.data
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

const text = z.string().min(1)
const timestamp = z.string().min(1)
const nullableText = z.string().nullish()

// ── Scores ──────────────────────────────────────────────────────────────────

/**
 * `Score = { passed, total, medianSeconds, runId, finishedAt, timeouts }`.
 * The score names no model: it belongs to whoever carries it.
 */
const scoreWire = z
  .object({
    passed: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
    medianSeconds: z.number().nonnegative().nullish(),
    runId: nullableText,
    finishedAt: nullableText,
    timeouts: z.number().int().nonnegative().nullish(),
  })
  .refine((score) => score.passed <= score.total, { message: 'passed exceeds total' })

function mapScore(value: unknown): ModelScore | null {
  if (value === undefined || value === null) return null
  const wire = parseOrFail(scoreWire, value, 'practice-suite score')
  return {
    passed: wire.passed,
    total: wire.total,
    medianSeconds: wire.medianSeconds ?? null,
    runId: wire.runId ?? null,
    finishedAt: wire.finishedAt ?? null,
    timeouts: wire.timeouts ?? null,
  }
}

// ── Consent ─────────────────────────────────────────────────────────────────

const termsWire = z.object({
  provider: z.string().min(1),
  url: z.string().min(1),
  text: z.string(),
  sha256: z.string().min(1),
})

const consentWire = z.object({
  destination: z.string().min(1),
  state: z.enum(['granted', 'not_granted', 'stale']),
  grantedAt: nullableText,
  grantedBy: nullableText,
  grantedTermsSha256: nullableText,
  terms: termsWire,
})

function mapConsent(value: unknown): ModelConsent {
  const wire = parseOrFail(consentWire, value, 'free-model consent')
  return {
    destination: wire.destination,
    state: wire.state,
    grantedAt: wire.grantedAt ?? null,
    grantedBy: wire.grantedBy ?? null,
    grantedTermsSha256: wire.grantedTermsSha256 ?? null,
    terms: {
      provider: wire.terms.provider,
      url: wire.terms.url,
      text: wire.terms.text,
      sha256: wire.terms.sha256,
    },
  }
}

// ── Catalogue ───────────────────────────────────────────────────────────────

const probeWire = z.object({
  status: z.string().min(1),
  cause: z.string().nullish(),
  at: nullableText,
  seconds: z.number().nonnegative().nullish(),
  sandboxStatus: z.string().nullish(),
  refusal: z.string().nullish(),
})

function mapProbe(value: unknown): ModelProbe | null {
  if (value === undefined || value === null) return null
  const wire = parseOrFail(probeWire, value, 'model probe')
  return {
    status: wire.status,
    cause: wire.cause ?? null,
    at: wire.at ?? null,
    seconds: wire.seconds ?? null,
    sandboxStatus: wire.sandboxStatus ?? null,
    refusal: wire.refusal ?? null,
  }
}

const catalogueResultWire = z.object({
  runId: nullableText,
  finishedAt: nullableText,
  state: z.string().nullish(),
  available: z.boolean().nullish(),
  complete: z.boolean().nullish(),
  passed: z.number().int().nonnegative().nullish(),
  total: z.number().int().nonnegative().nullish(),
  medianSeconds: z.number().nonnegative().nullish(),
  suiteDigest: z.string().nullish(),
  current: z.boolean().nullish(),
})

function mapCatalogueResult(value: unknown): CatalogueResult | null {
  if (value === undefined || value === null) return null
  const wire = parseOrFail(catalogueResultWire, value, 'catalogue result')
  return {
    runId: wire.runId ?? null,
    finishedAt: wire.finishedAt ?? null,
    state: wire.state ?? null,
    available: wire.available ?? null,
    complete: wire.complete ?? null,
    passed: wire.passed ?? null,
    total: wire.total ?? null,
    medianSeconds: wire.medianSeconds ?? null,
    suiteDigest: wire.suiteDigest ?? null,
    current: wire.current ?? null,
  }
}

const catalogueModelWire = z.object({
  id: text,
  free: z.boolean(),
  destination: z.string().min(1),
  listedNow: z.boolean(),
  usable: z.boolean(),
  firstSeenAt: nullableText,
  lastSeenAt: nullableText,
  seenCount: z.number().int().nonnegative().nullish(),
  lastProbe: z.unknown().optional(),
  latestResult: z.unknown().optional(),
})

const catalogueWire = z.object({
  observedAt: nullableText,
  observations: z.number().int().nonnegative().nullish(),
  harness: z.object({ id: text, version: nullableText }).nullish(),
  lastError: z.object({ code: text, at: nullableText }).nullish(),
  availabilityWindowSeconds: z.number().int().nonnegative().nullish(),
  cache: z.object({ path: text, sha256: text, storedAt: nullableText }).nullish(),
  models: z.array(catalogueModelWire),
})

function mapCatalogue(value: unknown): ModelCatalogue {
  const wire = parseOrFail(catalogueWire, value, 'model catalogue')
  const seen = new Set<string>()
  const models: CatalogueModel[] = []
  for (const entry of wire.models) {
    if (seen.has(entry.id)) failClosed(`model ${entry.id} is listed twice in the catalogue`)
    seen.add(entry.id)
    const free = entry.free ?? isFreeModelId(entry.id)
    models.push({
      id: entry.id,
      free,
      destination: entry.destination ?? (free ? FREE_DESTINATION : 'account'),
      listedNow: entry.listedNow,
      usable: entry.usable,
      firstSeenAt: entry.firstSeenAt ?? null,
      lastSeenAt: entry.lastSeenAt ?? null,
      seenCount: entry.seenCount ?? null,
      lastProbe: mapProbe(entry.lastProbe),
      latestResult: mapCatalogueResult(entry.latestResult),
    })
  }
  return {
    observedAt: wire.observedAt ?? null,
    observations: wire.observations ?? null,
    harness: wire.harness ? { id: wire.harness.id, version: wire.harness.version ?? null } : null,
    lastError: wire.lastError ? { code: wire.lastError.code, at: wire.lastError.at ?? '' } : null,
    availabilityWindowSeconds: wire.availabilityWindowSeconds ?? null,
    cache: wire.cache
      ? { path: wire.cache.path, sha256: wire.cache.sha256, storedAt: wire.cache.storedAt ?? '' }
      : null,
    models,
  }
}

// ── Status, alarms, routes ─────────────────────────────────────────────────

const alarmWire = z.object({
  code: text,
  model: z.string().nullish(),
  at: nullableText,
  detail: z.string().nullish(),
})

function mapAlarm(value: unknown): ModelAlarm | null {
  if (value === undefined || value === null) return null
  const wire = parseOrFail(alarmWire, value, 'model alarm')
  return { code: wire.code, model: wire.model ?? null, at: wire.at ?? '', detail: wire.detail ?? '' }
}

const statusWire = z.object({
  state: z.enum(['ready', 'not_consented', 'no_route', 'harness_unavailable']),
  detail: z.string(),
  harness: z.object({ id: text, present: z.boolean(), version: nullableText }),
  readyClasses: z.array(text).optional(),
  alarm: z.unknown().optional(),
})

function mapStatus(value: unknown): ModelsStatus {
  const wire = parseOrFail(statusWire, value, 'model route status')
  return {
    state: wire.state,
    detail: wire.detail,
    harness: { id: wire.harness.id, present: wire.harness.present, version: wire.harness.version ?? null },
    readyClasses: wire.readyClasses ?? [],
    alarm: mapAlarm(wire.alarm),
  }
}

const refusalWire = z.object({ code: text, message: z.string() })

const routeWire = z.object({
  actionClass: text,
  model: z.string().nullable(),
  pinned: z.boolean(),
  setBy: z.string().nullish(),
  setAt: nullableText,
  why: z.string().nullish(),
  ageSeconds: z.number().int().nonnegative().nullish(),
  score: z.unknown().optional(),
  usable: z.boolean().nullish(),
  refusal: z.unknown().optional(),
})

function mapRoutes(value: unknown): ModelRoute[] {
  if (!Array.isArray(value)) failClosed('routes were not a list')
  const seen = new Set<string>()
  return value.map((entry) => {
    const wire = parseOrFail(routeWire, entry, 'model route')
    if (seen.has(wire.actionClass)) failClosed(`action class ${wire.actionClass} has two routes`)
    seen.add(wire.actionClass)
    let refusal: ModelRouteRefusal | null = null
    if (wire.refusal !== undefined && wire.refusal !== null) {
      const parsed = parseOrFail(refusalWire, wire.refusal, `route refusal for ${wire.actionClass}`)
      refusal = { code: parsed.code, message: parsed.message }
    }
    return {
      actionClass: wire.actionClass,
      model: wire.model ?? null,
      pinned: wire.pinned,
      setBy: wire.setBy ?? null,
      setAt: wire.setAt ?? null,
      why: wire.why ?? null,
      ageSeconds: wire.ageSeconds ?? null,
      score: mapScore(wire.score),
      usable: wire.usable ?? null,
      refusal,
    }
  })
}

// ── Lease, proposal, receipts ───────────────────────────────────────────────

const leaseWire = z.object({
  enabled: z.boolean(),
  state: z.enum(['off', 'active', 'expired', 'inactive']),
  grantedAt: nullableText,
  expiresAt: nullableText,
  maxSuiteRunsPerDay: z.number().int().nonnegative().nullish(),
  runsToday: z.number().int().nonnegative().nullish(),
  maxDays: z.number().int().nonnegative().nullish(),
  defaultDays: z.number().int().nonnegative().nullish(),
})

function mapLease(value: unknown): ModelLease {
  const wire = parseOrFail(leaseWire, value, 'automatic-update lease')
  return {
    enabled: wire.enabled,
    state: wire.state,
    grantedAt: wire.grantedAt ?? null,
    expiresAt: wire.expiresAt ?? null,
    maxSuiteRunsPerDay: wire.maxSuiteRunsPerDay ?? null,
    runsToday: wire.runsToday ?? null,
    maxDays: wire.maxDays ?? null,
    defaultDays: wire.defaultDays ?? null,
  }
}

const proposalWire = z.object({
  id: text,
  actionClass: text,
  from: z.string().nullish(),
  to: text,
  reason: z.string().nullish(),
  why: z.string().nullish(),
  candidate: z.unknown().optional(),
  incumbent: z.unknown().optional(),
  suiteDigest: z.string().nullish(),
  createdAt: nullableText,
  status: z.string().min(1),
  summary: z.string().nullish(),
})

function mapProposal(value: unknown): RouteProposal | null {
  if (value === undefined || value === null) return null
  const wire = parseOrFail(proposalWire, value, 'route proposal')
  return {
    id: wire.id,
    actionClass: wire.actionClass,
    from: wire.from ?? null,
    to: wire.to,
    reason: wire.reason ?? null,
    why: wire.why ?? null,
    candidate: mapScore(wire.candidate),
    incumbent: mapScore(wire.incumbent),
    suiteDigest: wire.suiteDigest ?? null,
    createdAt: wire.createdAt ?? null,
    status: wire.status,
    summary: wire.summary ?? null,
  }
}

const receiptWire = z.object({
  receiptId: text,
  sequence: z.number().int().nullish(),
  type: text,
  at: timestamp,
  by: z.string().nullish(),
})

/** One plain sentence per receipt; the service's own fields, never invented. */
function receiptSummary(wire: z.infer<typeof receiptWire>, extra: Record<string, unknown>): string {
  const from = typeof extra.from === 'string' ? extra.from : null
  const to = typeof extra.to === 'string' ? extra.to : null
  const model = typeof extra.model === 'string' ? extra.model : null
  const why = typeof extra.why === 'string' ? extra.why : null
  switch (wire.type) {
    case 'consent.granted':
      return 'Free-model terms accepted.'
    case 'consent.withdrawn':
      return 'Free-model consent withdrawn.'
    case 'catalogue.observed': {
      const added = typeof extra.added === 'number' ? extra.added : null
      const vanished = typeof extra.vanished === 'number' ? extra.vanished : null
      const parts = [
        added === null ? null : `${added} new`,
        vanished === null ? null : `${vanished} gone`,
      ].filter((part): part is string => part !== null)
      return parts.length > 0 ? `Model list checked: ${parts.join(', ')}.` : 'Model list checked.'
    }
    case 'catalogue.observation_failed':
      return 'Checking the model list failed.'
    case 'model.probed':
      return model ? `Probed ${model}.` : 'Probed a model.'
    case 'suite.run_started':
      return 'Practice tasks started.'
    case 'suite.run_finished':
      return 'Practice tasks finished.'
    case 'route.changed': {
      const change = from ? `Route changed from ${from} to ${to ?? 'none'}` : `Route set to ${to ?? 'none'}`
      return why ? `${change}: ${why}` : `${change}.`
    }
    case 'proposal.created':
      return `Proposal: switch to ${to ?? 'none'}.`
    case 'proposal.dismissed':
      return 'Proposal dismissed.'
    case 'lease.granted':
      return 'Automatic updates granted.'
    case 'lease.revoked':
      return 'Automatic updates revoked.'
    case 'lease.expired':
      return 'Automatic updates expired.'
    case 'harness.alarm':
      return `Harness alarm: ${extra.detail ? String(extra.detail) : 'the model harness reported a problem'}.`
    case 'schedule.tick':
      return 'Automatic check ran.'
    default:
      return wire.type.replaceAll('_', ' ')
  }
}

function mapReceipts(value: unknown): ModelsReceipt[] {
  if (!Array.isArray(value)) failClosed('receipts were not a list')
  return value.map((entry) => {
    if (!isRecord(entry)) failClosed('a receipt was not an object')
    const wire = parseOrFail(receiptWire, entry, 'model receipt')
    return {
      id: wire.receiptId,
      sequence: wire.sequence ?? null,
      type: wire.type,
      at: wire.at,
      by: wire.by ?? null,
      summary: receiptSummary(wire, entry),
    }
  })
}

// ── Suite, evaluation, schedule ─────────────────────────────────────────────

const suiteWire = z.union([
  z.object({
    valid: z.literal(true),
    id: text,
    // The service publishes the frozen suite version as a whole number; older
    // projections carried a string. Both are the same fact.
    version: z.union([z.string().min(1), z.number().int().nonnegative()]).nullish(),
    digest: z.string().nullish(),
    taskCount: z.number().int().nonnegative().nullish(),
    taskTimeoutSeconds: z.number().int().nonnegative().nullish(),
    tasks: z.array(z.object({ id: text, title: z.string().nullish(), critical: z.boolean().nullish() })),
  }),
  z.object({ valid: z.literal(false), reason: text }),
])

function mapSuite(value: unknown): ModelsSuite {
  const wire = parseOrFail(suiteWire, value, 'practice-suite summary')
  if (!wire.valid) {
    return {
      valid: false,
      id: null,
      version: null,
      digest: null,
      taskCount: null,
      taskTimeoutSeconds: null,
      tasks: [],
      reason: wire.reason ?? null,
    }
  }
  return {
    valid: true,
    id: wire.id,
    version: wire.version === undefined || wire.version === null ? null : String(wire.version),
    digest: wire.digest ?? null,
    taskCount: wire.taskCount ?? null,
    taskTimeoutSeconds: wire.taskTimeoutSeconds ?? null,
    tasks: wire.tasks.map((task) => ({
      id: task.id,
      title: task.title ?? task.id,
      critical: task.critical ?? false,
    })),
    reason: null,
  }
}

const evaluationWire = z.object({
  activeRunId: z.string().nullish(),
  maxModels: z.number().int().nonnegative().nullish(),
  lastRunId: z.string().nullish(),
})

function mapEvaluation(value: unknown): ModelsEvaluation {
  const wire = parseOrFail(evaluationWire, value, 'evaluation state')
  return {
    activeRunId: wire.activeRunId ?? null,
    maxModels: wire.maxModels ?? null,
    lastRunId: wire.lastRunId ?? null,
  }
}

const scheduleWire = z.object({
  running: z.boolean(),
  intervalSeconds: z.number().int().nonnegative().nullish(),
  nextTickAt: nullableText,
})

function mapSchedule(value: unknown): ModelsSchedule {
  const wire = parseOrFail(scheduleWire, value, 'automatic-update schedule')
  return {
    running: wire.running,
    intervalSeconds: wire.intervalSeconds ?? null,
    nextTickAt: wire.nextTickAt ?? null,
  }
}

// ── View ────────────────────────────────────────────────────────────────────

/** GET /v1/models → ModelsView. */
export function mapModelsView(payload: unknown): ModelsView {
  if (!isRecord(payload)) failClosed('the models projection was not an object')
  if (payload.formatVersion !== undefined && payload.formatVersion !== 'stateport.models-projection/v1') {
    failClosed('the models projection had an unknown format version', String(payload.formatVersion))
  }
  return {
    status: mapStatus(payload.status),
    consent: mapConsent(payload.consent),
    catalogue: mapCatalogue(payload.catalogue),
    alarms: Array.isArray(payload.alarms)
      ? payload.alarms.map((entry) => mapAlarm(entry)).filter((entry): entry is ModelAlarm => entry !== null)
      : [],
    routes: mapRoutes(payload.routes),
    lease: mapLease(payload.lease),
    suite: mapSuite(payload.suite),
    evaluation: mapEvaluation(payload.evaluation),
    proposal: mapProposal(payload.proposal),
    proposals: Array.isArray(payload.proposals)
      ? payload.proposals
          .map((entry) => mapProposal(entry))
          .filter((entry): entry is RouteProposal => entry !== null)
      : [],
    schedule: mapSchedule(payload.schedule),
    receipts: mapReceipts(payload.receipts),
    scoresNote:
      typeof payload.scoresNote === 'string' && payload.scoresNote
        ? payload.scoresNote
        : 'Scores come from StatePort\'s practice tasks, not from your work.',
  }
}

// ── Suite runs ──────────────────────────────────────────────────────────────

const RUN_STATES: Record<string, SuiteRunState> = {
  queued: 'queued',
  running: 'running',
  completed: 'completed',
  failed: 'failed',
  interrupted: 'interrupted',
}

const taskWire = z.object({
  taskId: text,
  passed: z.boolean().nullish(),
  seconds: z.number().nonnegative().nullish(),
  reason: z.string().nullish(),
  status: z.string().nullish(),
})

const modelResultWire = z.object({
  model: text,
  probe: z.unknown().optional(),
  available: z.boolean(),
  complete: z.boolean(),
  isRetry: z.boolean(),
  timeouts: z.number().int().nonnegative().nullish(),
  totals: z.unknown().optional(),
  tasks: z.array(taskWire),
})

const suiteRunWire = z.object({
  runId: text,
  state: text,
  error: z.string().nullish(),
  trigger: z.string().nullish(),
  by: z.string().nullish(),
  createdAt: nullableText,
  startedAt: nullableText,
  finishedAt: nullableText,
  requestedModels: z.array(text),
  progress: z.object({
    completedTasks: z.number().int().nonnegative(),
    totalTasks: z.number().int().nonnegative(),
    currentModel: z.string().nullish(),
    currentTask: z.string().nullish(),
  }),
  models: z.array(modelResultWire),
})

function probeCauseOf(probe: unknown): string | null {
  if (!probe || typeof probe !== 'object') return null
  const cause = (probe as { cause?: unknown }).cause
  return typeof cause === 'string' && cause ? cause : null
}

/** GET /v1/models/runs/<runId> → ModelSuiteRun (identity-bound to the request). */
export function mapSuiteRun(payload: unknown, expectedRunId: string): ModelSuiteRun {
  const wire = parseOrFail(suiteRunWire, payload, 'practice-suite run')
  if (wire.runId !== expectedRunId) {
    failClosed('the practice-suite run identity changed', `expected ${expectedRunId}, got ${wire.runId}`)
  }
  const state = RUN_STATES[wire.state]
  if (!state) failClosed(`unknown practice-suite run state "${wire.state}"`)
  const models: SuiteModelResult[] = wire.models.map((entry) => {
    const tasks: SuiteTaskResult[] = entry.tasks.map((task) => ({
      taskId: task.taskId,
      passed: task.passed ?? null,
      seconds: task.seconds ?? null,
      reason: task.reason ?? null,
      status: task.status ?? (task.passed === null ? 'not_run' : 'checked'),
    }))
    return {
      model: entry.model,
      available: entry.available,
      complete: entry.complete,
      isRetry: entry.isRetry,
      timeouts: entry.timeouts ?? null,
      totals: mapScore(entry.totals),
      tasks,
      probeCause: probeCauseOf(entry.probe),
    }
  })
  return {
    runId: wire.runId,
    state,
    trigger: wire.trigger ?? null,
    by: wire.by ?? null,
    createdAt: wire.createdAt ?? null,
    startedAt: wire.startedAt ?? null,
    finishedAt: wire.finishedAt ?? null,
    error: wire.error ?? null,
    requestedModels: wire.requestedModels,
    progress: {
      completedTasks: wire.progress.completedTasks,
      totalTasks: wire.progress.totalTasks,
      currentModel: wire.progress.currentModel ?? null,
      currentTask: wire.progress.currentTask ?? null,
    },
    models,
  }
}

/** POST /v1/models/evaluate → {runId}. */
export function mapEvaluateResponse(payload: unknown): { runId: string } {
  const wire = parseOrFail(z.object({ runId: text }), payload, 'evaluation start')
  return { runId: wire.runId }
}
