/**
 * Model routes (ADR-0007 §3 level 1, docs/design/keep-up-loop.md): the
 * browser-side domain contract behind Settings → Models, agent-action
 * readiness and first-run onboarding.
 *
 * The domain shapes mirror `GET /v1/models` — the
 * `stateport.models-projection/v1` projection documented in
 * `docs/API_CONTRACT_WEB.md` §"Model routes" — exactly. The wire schemas and
 * mappers live in `http/modelsWire.ts`; the transport client in
 * `http/domainsModels.ts`. Integrating a changed backend shape touches
 * `modelsWire.ts` only.
 *
 * Honesty rules:
 * - No route is ever assumed. A missing route, consent, lease or score is
 *   represented as `null`/`false`, never as a default "ready".
 * - Scores are StatePort practice-task results (the frozen model suite), never
 *   measurements of the owner's own work.
 */

/** The only consent-gated destination in Alpha.26: OpenCode's free models. */
export const FREE_DESTINATION = 'opencode-free' as const
/** The action class an agent action runs under (keep-up-loop.md, policy.json routes). */
export const AGENT_ACTION_CLASS = 'agent.edit-state' as const
/** The second action class the service routes independently (chat). */
export const CHAT_ACTION_CLASS = 'chat' as const
/** keep-up-loop.md: `POST /v1/models/evaluate` accepts at most three models. */
export const MAX_MODELS_PER_EVALUATION = 3
/** keep-up-loop.md: "Keep up automatically" is granted for 30 days. */
export const LEASE_DAYS = 30

export type ModelDestination = typeof FREE_DESTINATION | 'account'

/** `status.state` of the projection. "ready" is never a promise of an answer. */
export type ModelsStatusState = 'ready' | 'not_consented' | 'no_route' | 'harness_unavailable'

export interface ModelAlarm {
  code: string
  model: string | null
  at: string
  detail: string
}

export interface ModelsStatus {
  state: ModelsStatusState
  detail: string
  harness: { id: string; present: boolean; version: string | null }
  /** Action classes whose route resolves right now. */
  readyClasses: string[]
  alarm: ModelAlarm | null
}

/** The provider's terms, quoted exactly as the service recorded them. */
export interface ModelTerms {
  provider: string
  url: string
  /** Shown verbatim to the owner; never re-worded here. */
  text: string
  /** `"sha256:<hex>"`; sent back unchanged when the owner accepts. */
  sha256: string
}

export type ModelConsentState = 'granted' | 'not_granted' | 'stale'

export interface ModelConsent {
  destination: string
  state: ModelConsentState
  grantedAt: string | null
  grantedBy: string | null
  grantedTermsSha256: string | null
  terms: ModelTerms
}

/**
 * One practice-suite measurement of one model. The score names no model: it
 * belongs to the route, catalogue entry or proposal that carries it.
 */
export interface ModelScore {
  passed: number
  total: number
  medianSeconds: number | null
  runId: string | null
  finishedAt: string | null
  timeouts: number | null
}

/** The catalogue's own record of a model's last measured run. */
export interface CatalogueResult {
  runId: string | null
  finishedAt: string | null
  state: string | null
  available: boolean | null
  complete: boolean | null
  passed: number | null
  total: number | null
  medianSeconds: number | null
  suiteDigest: string | null
  /** True when the measurement belongs to the current frozen suite. */
  current: boolean | null
}

export interface ModelProbe {
  status: string
  cause: string | null
  at: string | null
  seconds: number | null
  sandboxStatus: string | null
  refusal: string | null
}

export interface CatalogueModel {
  id: string
  free: boolean
  destination: string
  /** The model was in the most recent observation. */
  listedNow: boolean
  /** The service considers it usable right now (recently seen, last probe ok). */
  usable: boolean
  firstSeenAt: string | null
  lastSeenAt: string | null
  seenCount: number | null
  lastProbe: ModelProbe | null
  latestResult: CatalogueResult | null
}

export interface ModelCatalogue {
  observedAt: string | null
  observations: number | null
  harness: { id: string; version: string | null } | null
  lastError: { code: string; at: string } | null
  availabilityWindowSeconds: number | null
  cache: { path: string; sha256: string; storedAt: string } | null
  models: CatalogueModel[]
}

/** The typed refusal an agent action receives when a route cannot resolve. */
export interface ModelRouteRefusal {
  code: string
  message: string
}

export interface ModelRoute {
  actionClass: string
  /** `null` means "none": actions of this class cannot run. */
  model: string | null
  pinned: boolean
  setBy: string | null
  setAt: string | null
  why: string | null
  ageSeconds: number | null
  score: ModelScore | null
  usable: boolean | null
  refusal: ModelRouteRefusal | null
}

export type ModelLeaseState = 'off' | 'active' | 'expired' | 'inactive'

export interface ModelLease {
  enabled: boolean
  state: ModelLeaseState
  grantedAt: string | null
  expiresAt: string | null
  maxSuiteRunsPerDay: number | null
  runsToday: number | null
  maxDays: number | null
  defaultDays: number | null
}

/** A pending route change the owner can Switch to or Dismiss. */
export interface RouteProposal {
  id: string
  actionClass: string
  from: string | null
  to: string
  reason: string | null
  why: string | null
  candidate: ModelScore | null
  incumbent: ModelScore | null
  suiteDigest: string | null
  createdAt: string | null
  status: string
  /** The service's own one-line summary of the change. */
  summary: string | null
}

export interface ModelsReceipt {
  id: string
  sequence: number | null
  /** The receipt type, e.g. `consent.granted` or `route.changed`. */
  type: string
  at: string
  by: string | null
  summary: string
}

export interface ModelsSuiteTask {
  id: string
  title: string
  critical: boolean
}

export interface ModelsSuite {
  valid: boolean
  id: string | null
  version: string | null
  digest: string | null
  taskCount: number | null
  taskTimeoutSeconds: number | null
  tasks: ModelsSuiteTask[]
  /** Why the frozen suite could not be read (when `valid` is false). */
  reason: string | null
}

export interface ModelsEvaluation {
  activeRunId: string | null
  maxModels: number | null
  lastRunId: string | null
}

export interface ModelsSchedule {
  running: boolean
  intervalSeconds: number | null
  nextTickAt: string | null
}

export interface ModelsView {
  status: ModelsStatus
  consent: ModelConsent
  catalogue: ModelCatalogue
  alarms: ModelAlarm[]
  routes: ModelRoute[]
  lease: ModelLease
  suite: ModelsSuite
  evaluation: ModelsEvaluation
  /** The newest pending proposal. */
  proposal: RouteProposal | null
  /** Every pending proposal. */
  proposals: RouteProposal[]
  schedule: ModelsSchedule
  receipts: ModelsReceipt[]
  /** The service's plain-language note about what the scores mean. */
  scoresNote: string
}

export type SuiteRunState = 'queued' | 'running' | 'completed' | 'failed' | 'interrupted'

export interface SuiteTaskResult {
  taskId: string
  passed: boolean | null
  seconds: number | null
  reason: string | null
  status: string
}

export interface SuiteModelResult {
  model: string
  /** The model answered the probe; "available now", never a quality claim. */
  available: boolean
  complete: boolean
  isRetry: boolean
  timeouts: number | null
  totals: ModelScore | null
  tasks: SuiteTaskResult[]
  /** Why the probe did not get an answer (free_usage_limit, rate_limited, timeout, ...); null when it did. */
  probeCause: string | null
}

export interface ModelSuiteRun {
  runId: string
  state: SuiteRunState
  trigger: string | null
  by: string | null
  createdAt: string | null
  startedAt: string | null
  finishedAt: string | null
  error: string | null
  requestedModels: string[]
  progress: {
    completedTasks: number
    totalTasks: number
    currentModel: string | null
    currentTask: string | null
  }
  models: SuiteModelResult[]
}

/** Typed client for the `/v1/models*` API (keep-up-loop.md "API"). */
export interface ModelsClient {
  /** GET /v1/models */
  getView(): Promise<ModelsView>
  /** POST /v1/models/consent {destination, termsSha256} */
  grantConsent(input: { destination: string; termsSha256: string }): Promise<void>
  /** DELETE /v1/models/consent {destination} */
  withdrawConsent(destination: string): Promise<void>
  /** POST /v1/models/observe {} */
  observe(): Promise<void>
  /** POST /v1/models/evaluate {models} → {runId} */
  evaluate(models: string[]): Promise<{ runId: string }>
  /** GET /v1/models/runs/<runId> */
  getRun(runId: string): Promise<ModelSuiteRun>
  /** POST /v1/models/route {actionClass, model, pin} */
  setRoute(input: { actionClass: string; model: string | null; pin: boolean }): Promise<void>
  /** POST /v1/models/lease {enabled, days} */
  setLease(input: { enabled: boolean; days: number }): Promise<void>
  /** POST /v1/models/proposal/<id> {decision} */
  decideProposal(proposalId: string, decision: 'switch' | 'dismiss'): Promise<void>
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure helpers
// ─────────────────────────────────────────────────────────────────────────────

/** keep-up-loop.md: the `free` flag is "id ends in -free" on the OpenCode route. */
export function isFreeModelId(modelId: string): boolean {
  return modelId.endsWith('-free')
}

export function destinationOf(modelId: string): ModelDestination {
  return isFreeModelId(modelId) ? FREE_DESTINATION : 'account'
}

export function routeFor(view: ModelsView, actionClass: string): ModelRoute | undefined {
  return view.routes.find((route) => route.actionClass === actionClass)
}

export function freeModelsConsented(view: ModelsView): boolean {
  return view.consent.state === 'granted'
}

export type AgentRouteReadiness =
  | { ready: true; model: string; destination: ModelDestination; route: ModelRoute }
  | { ready: false; code: string; reason: string }

/**
 * Whether an agent action of `actionClass` may run now. A route counts only
 * when it names a model AND, for the free destination, consent is recorded.
 */
export function agentRouteReadiness(
  view: ModelsView,
  actionClass: string = AGENT_ACTION_CLASS,
): AgentRouteReadiness {
  const route = routeFor(view, actionClass)
  if (!route?.model) {
    return {
      ready: false,
      code: route?.refusal?.code ?? 'route_not_configured',
      reason: route?.refusal?.message
        ?? 'No model is chosen for agent actions yet. Allow and evaluate the free models on Settings → Models.',
    }
  }
  const destination = destinationOf(route.model)
  if (destination === FREE_DESTINATION && !freeModelsConsented(view)) {
    return {
      ready: false,
      code: route.refusal?.code ?? 'route_not_consented',
      reason: route.refusal?.message
        ?? 'Agent actions use free models, which need your consent first. Review the terms on Settings → Models.',
    }
  }
  if (view.status.harness.present === false) {
    return {
      ready: false,
      code: 'harness_unavailable',
      reason: view.status.detail
        ?? 'The model program is not available on this machine, so agent actions cannot run.',
    }
  }
  return { ready: true, model: route.model, destination, route }
}

export function destinationLabel(destination: string | null): string {
  if (destination === FREE_DESTINATION) return 'free model, no account'
  if (destination === 'account') return 'your own account'
  return 'unknown destination'
}

const ACTION_CLASS_LABELS: Record<string, string> = {
  [AGENT_ACTION_CLASS]: 'Agent actions (propose changes to an application)',
  [CHAT_ACTION_CLASS]: 'Chat (the assistant answers with this model)',
}

export function actionClassLabel(actionClass: string): string {
  return ACTION_CLASS_LABELS[actionClass] ?? actionClass
}

/** "3/4" or "Not measured". */
export function scoreFraction(score: ModelScore | null | undefined): string {
  return score ? `${score.passed}/${score.total}` : 'Not measured'
}

/** "41 s" (rounded) or "—". */
export function secondsLabel(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—'
  return `${Math.round(seconds)} s`
}

/** "3/4 · median 41 s" or "Not measured". */
export function scoreLabel(score: ModelScore | null | undefined): string {
  if (!score) return 'Not measured'
  return score.medianSeconds === null
    ? scoreFraction(score)
    : `${scoreFraction(score)} · median ${secondsLabel(score.medianSeconds)}`
}

/** The catalogue's own last-result record as a score, when it is a measurement. */
export function catalogueScore(result: CatalogueResult | null | undefined): ModelScore | null {
  if (!result) return null
  if (result.passed === null || result.total === null) return null
  return {
    passed: result.passed,
    total: result.total,
    medianSeconds: result.medianSeconds,
    runId: result.runId,
    finishedAt: result.finishedAt,
    timeouts: null,
  }
}

/** keep-up-loop.md: "Switch to X: 3/3 vs 2/3, 41 s vs 63 s". */
export function proposalSentence(proposal: RouteProposal): string {
  if (proposal.summary) return proposal.summary
  const scores = `${scoreFraction(proposal.candidate)} vs ${scoreFraction(proposal.incumbent)}`
  const times =
    proposal.candidate?.medianSeconds != null || proposal.incumbent?.medianSeconds != null
      ? `, ${secondsLabel(proposal.candidate?.medianSeconds)} vs ${secondsLabel(proposal.incumbent?.medianSeconds)}`
      : ''
  return `Switch to ${proposal.to}: ${scores}${times}`
}

/** "2 minutes ago" from the service's own age in seconds. */
export function ageLabel(ageSeconds: number | null | undefined): string | null {
  if (ageSeconds === null || ageSeconds === undefined) return null
  if (ageSeconds < 90) return `${Math.max(0, Math.round(ageSeconds))} s ago`
  const minutes = Math.round(ageSeconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.round(minutes / 60)
  if (hours < 48) return `${hours} h ago`
  return `${Math.round(hours / 24)} days ago`
}

export function suiteRunSettled(run: ModelSuiteRun): boolean {
  return run.state === 'completed' || run.state === 'failed' || run.state === 'interrupted'
}
