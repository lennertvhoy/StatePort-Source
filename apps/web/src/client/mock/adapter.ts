/**
 * MockClient — the deterministic, latency-simulated reference implementation
 * of `StatePortClient`. It must feel like a real product:
 *
 * - Latency 80–250 ms per call (deterministic sequence per adapter instance),
 *   scaled by the active scenario (e.g. "Slow service").
 * - Believable state machines: terminal command interpreter, chunked
 *   conversation streaming with stop/retry, infra plan→approve→run→validate
 *   →receipt, governed file writes with conflict + path-policy rejections,
 *   stale-digest approval rejection, the 13-stage orchestration flow, and
 *   authorization grant/revoke with expiry.
 * - State persists (debounced) under `stateport.mock.v1`; terminal sessions
 *   are deliberately in-memory only (refresh never silently reconnects).
 * - The active scenario overrides *behavior*; scenario-materialized entities
 *   live in a volatile `extras` overlay, never in the seeded database.
 */
import type {
  ActivityFilter,
  ActivityItem,
  ApplicationInstance,
  Approval,
  ApprovalFilter,
  AppSettings,
  Attachment,
  AttentionItem,
  AuthorizationGrant,
  BuildInfo,
  CanonicalSourceOperatorView,
  CanonicalSourcePublicView,
  CatalogPackage,
  CommandResult,
  ContextChip,
  ContextLifecycle,
  Conversation,
  ConversationMessage,
  ConversationStreamChunk,
  DevelopmentSourceResolution,
  FileDiff,
  FileEntry,
  FileNode,
  GlobalSettings,
  GlobalSettingsRollbackHistory,
  GlobalSettingsRollbackTarget,
  InfrastructureOperation,
  InfrastructurePlan,
  InfrastructureTarget,
  LocalServiceStatus,
  MessageStream,
  NotificationItem,
  OperationRecord,
  OrchestrationSession,
  PlanProgressEvent,
  Receipt,
  ReceiptFilter,
  RepositoryRegistration,
  RunRecord,
  SessionInfo,
  TerminalSession,
  TerminalSessionEvent,
  TerminalTarget,
  WriteFileResult,
} from '../types'
import { canInspectPlatformStateBench, ClientError } from '../types'
import { checkAttachment } from '../attachmentPolicy'
import type { DeepPartial, StatePortClient } from '../client'
import { schemas } from '../schemas'
import { assertSettingsImportSize } from '../settingsImportPolicy'
import { z } from 'zod'
import {
  INSTANCE_IDS,
  TARGET_IDS,
  buildFileTree,
  buildSeed,
  defaultGlobalSettings,
  fakeDigest,
  fakeHex,
  nextId,
} from './seed'
import type { MockDatabase, MockFileRecord } from './seed'
import { clearMockStorage, flushMockWrites, loadMockEnvelope, saveMockEnvelope } from './store'
import { SCENARIOS, getActiveBehavior, useScenarioStore } from './scenarios'
import type { ScenarioId } from './scenarios'
import {
  isStudyStateCaptureRequested,
  STUDYSTATE_CAPTURE_NOW_MS,
} from './capture'

// ─────────────────────────────────────────────────────────────────────────────
// Small utilities
// ─────────────────────────────────────────────────────────────────────────────

function prng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

type SettingsScalar = string | number | boolean

function globalServiceValues(settings: GlobalSettings): Record<string, SettingsScalar> {
  const values: Record<string, SettingsScalar> = {
    'notifications.level':
      settings.notifications.level === 'important_only'
        ? 'important'
        : settings.notifications.level,
  }
  if (settings.appearance.theme !== 'high_contrast') {
    values['general.appearance'] = settings.appearance.theme
  }
  if (settings.general.defaultLandingPage === 'applications') {
    values['general.defaultLandingView'] = 'home'
  }
  return values
}

function changedGlobalServiceValues(
  before: GlobalSettings,
  after: GlobalSettings,
): {
  changes: Record<string, SettingsScalar>
  previousValues: Record<string, SettingsScalar>
} {
  const beforeValues = globalServiceValues(before)
  const afterValues = globalServiceValues(after)
  const changes: Record<string, SettingsScalar> = {}
  const previousValues: Record<string, SettingsScalar> = {}
  for (const [key, value] of Object.entries(afterValues)) {
    if (key in beforeValues && beforeValues[key] !== value) {
      changes[key] = value
      previousValues[key] = beforeValues[key]
    }
  }
  return { changes, previousValues }
}

function applyGlobalServiceValues(
  current: GlobalSettings,
  values: Record<string, SettingsScalar>,
): GlobalSettings {
  const restored = structuredClone(current)
  const appearance = values['general.appearance']
  if (
    restored.appearance.theme !== 'high_contrast' &&
    (appearance === 'system' || appearance === 'light' || appearance === 'dark')
  ) {
    restored.appearance.theme = appearance
  }
  const landing = values['general.defaultLandingView']
  if (
    restored.general.defaultLandingPage !== 'last_workspace' &&
    (landing === 'home' || landing === 'catalog')
  ) {
    restored.general.defaultLandingPage = 'applications'
  }
  const level = values['notifications.level']
  if (level === 'all' || level === 'none' || level === 'important') {
    restored.notifications.level = level === 'important' ? 'important_only' : level
  }
  return restored
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))
const nowIso = () => new Date().toISOString()

const MOCK_SOURCE_ID = 'stateport.source.studystate'
const MOCK_SOURCE_REPOSITORY = 'https://github.com/example/studystate-template.git'
const MOCK_SOURCE_COMMIT = '7b8a6449361578264952f985d70655233e870b4e'
const MOCK_SOURCE_TREE = '3ade73c663dcb48fb4992138a0a135e5640959ba'
const MOCK_MANIFEST_DIGEST = `sha256:${'4'.repeat(64)}`
const MOCK_SOURCE_DIGEST = `sha256:${'6'.repeat(64)}`
const MOCK_ACKNOWLEDGEMENT = `sha256:${'a'.repeat(64)}`

const MOCK_PUBLIC_SOURCE: CanonicalSourcePublicView = {
  formatVersion: 'stateport.canonical-source-public-view/v1',
  sourceId: MOCK_SOURCE_ID,
  applicationId: 'study-state',
  publicName: 'StudyState',
  status: 'awaiting_verified_release',
  installable: false,
  productionAction: { action: 'install_or_update', enabled: false },
  message: 'Application source is awaiting a verified release.',
}

const MOCK_OPERATOR_SOURCE: CanonicalSourceOperatorView = {
  formatVersion: 'stateport.canonical-source-operator-view/v1',
  sourceId: MOCK_SOURCE_ID,
  application: {
    id: 'study-state',
    publicName: 'StudyState',
    legacyIdentifiers: ['studydd', 'StudyDD_Template'],
  },
  authority: {
    repository: MOCK_SOURCE_REPOSITORY,
    canonicalRefPolicy: 'immutable_release_tag',
    manifestPath: '.statedd/manifest.yaml',
    manifestContract: 'statedd.template-manifest/v2',
  },
  canonicalRelease: {
    sourceClass: 'canonical_release',
    identity: null,
    status: 'awaiting_verified_release',
    trust: 'development_only',
    installable: false,
    missingRequirement: 'canonical_release_not_published',
    requiredModules: ['studydd.core', 'studydd.activities'],
    expectedSelfTests: ['core-health', 'activities-contract'],
  },
  developmentCandidate: {
    sourceClass: 'development_candidate',
    releaseStatus: 'candidate',
    testingAllowed: true,
    productionInstallAllowed: false,
    identity: {
      repository: MOCK_SOURCE_REPOSITORY,
      commit: MOCK_SOURCE_COMMIT,
      tree: MOCK_SOURCE_TREE,
      manifestDigest: MOCK_MANIFEST_DIGEST,
      sourceDigest: MOCK_SOURCE_DIGEST,
    },
    verifiedModules: ['studydd.core', 'studydd.activities'],
    verifiedSelfTests: ['core-health', 'activities-contract'],
    verificationAction: {
      enabled: true,
      acknowledgement: MOCK_ACKNOWLEDGEMENT,
      purpose: 'isolated_development_verification_only',
    },
  },
  message: 'Application source is awaiting a verified release.',
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario-seeded live stream ("Conversation streaming")
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The conversation_streaming scenario seeds one in-flight assistant reply.
 * The id is stable so a resume re-attaches to this exact message instead of
 * duplicating it.
 */
const STREAMING_SCENARIO_MESSAGE_ID = 'msg_scn_streaming'

/** The seeded reply's full text; the seeded view carries only its prefix. */
const STREAMING_SCENARIO_FULL_TEXT =
  'Looking at the current plan and the repository state, the first thing to note is that nothing has run yet: the plan to start `homelab-dev` is still waiting for approval, and the repository `nixos-homelab` is clean on `main`.\n\nOnce the plan is approved and the VM reports ready, the next step is validating the flake and running the health check so the target shows a verified state again.'

const STREAMING_SCENARIO_PREFIX_LENGTH = 'Looking at the current plan and the repository state, the first thing to note is'.length

function scenarioStreamingMessage(conversationId: string, now = Date.now()): ConversationMessage {
  return {
    id: STREAMING_SCENARIO_MESSAGE_ID,
    conversationId,
    role: 'assistant',
    content: STREAMING_SCENARIO_FULL_TEXT.slice(0, STREAMING_SCENARIO_PREFIX_LENGTH),
    createdAt: new Date(now).toISOString(),
    state: 'streaming',
    attachments: [],
    contextChips: [],
    toolEvents: [],
  }
}

function deepMerge<T>(base: T, patch: DeepPartial<T>): T {
  if (Array.isArray(base) || Array.isArray(patch) || typeof base !== 'object' || base === null) {
    return (patch === undefined ? base : (patch as T))
  }
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) }
  for (const [k, v] of Object.entries(patch as Record<string, unknown>)) {
    if (v === undefined) continue
    const cur = out[k]
    out[k] =
      cur && typeof cur === 'object' && !Array.isArray(cur) && typeof v === 'object' && !Array.isArray(v)
        ? deepMerge(cur, v as DeepPartial<typeof cur>)
        : v
  }
  return out as T
}

/** Minimal unified line diff (single-hunk friendly, believable for save previews). */
export function unifiedDiff(path: string, before: string, after: string): FileDiff {
  const a = before.split('\n')
  const b = after.split('\n')
  // LCS table
  const m = a.length
  const n = b.length
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0))
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1])
    }
  }
  const lines: string[] = []
  let i = 0
  let j = 0
  let added = 0
  let removed = 0
  const CONTEXT = 3
  const ops: { t: ' ' | '+' | '-'; s: string }[] = []
  while (i < m && j < n) {
    if (a[i] === b[j]) {
      ops.push({ t: ' ', s: a[i] })
      i++
      j++
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      ops.push({ t: '-', s: a[i] })
      removed++
      i++
    } else {
      ops.push({ t: '+', s: b[j] })
      added++
      j++
    }
  }
  while (i < m) {
    ops.push({ t: '-', s: a[i] })
    removed++
    i++
  }
  while (j < n) {
    ops.push({ t: '+', s: b[j] })
    added++
    j++
  }
  // Trim leading/trailing context to CONTEXT lines around first/last change.
  const firstChange = ops.findIndex((o) => o.t !== ' ')
  const lastChange = ops.length - 1 - [...ops].reverse().findIndex((o) => o.t !== ' ')
  let start = 0
  let end = ops.length
  if (firstChange !== -1) {
    start = Math.max(0, firstChange - CONTEXT)
    end = Math.min(ops.length, lastChange + 1 + CONTEXT)
  }
  const slice = ops.slice(start, end)
  const aStart = start + 1
  const bStart = start + 1
  const aCount = slice.filter((o) => o.t !== '+').length
  const bCount = slice.filter((o) => o.t !== '-').length
  lines.push(`--- a/${path}`)
  lines.push(`+++ b/${path}`)
  if (firstChange !== -1) {
    lines.push(`@@ -${aStart},${aCount} +${bStart},${bCount} @@`)
    for (const o of slice) lines.push(`${o.t}${o.s}`)
  }
  return { unified: lines.join('\n'), addedLines: added, removedLines: removed }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario extras overlay (volatile; discarded on scenario change)
// ─────────────────────────────────────────────────────────────────────────────

interface ScenarioExtras {
  key: string
  plans: InfrastructurePlan[]
  approvals: Approval[]
  operations: OperationRecord[]
  orchestration: Record<string, OrchestrationSession>
  authorizations: Record<string, AuthorizationGrant>
}

const EMPTY_EXTRAS: ScenarioExtras = {
  key: '',
  plans: [],
  approvals: [],
  operations: [],
  orchestration: {},
  authorizations: {},
}

/**
 * Fresh mutable collections per rebuild: a shallow spread of EMPTY_EXTRAS
 * would share the nested maps/arrays, leaking one scenario's seeded extras
 * into every later behavior (including ones that seed nothing).
 */
function emptyExtras(key = ''): ScenarioExtras {
  return { key, plans: [], approvals: [], operations: [], orchestration: {}, authorizations: {} }
}

// ─────────────────────────────────────────────────────────────────────────────
// MockClient
// ─────────────────────────────────────────────────────────────────────────────

const dbSchema = z.object({
  instances: z.array(schemas.applicationInstance),
  globalSettings: schemas.globalSettings,
  receipts: z.record(z.string(), schemas.receipt),
  approvals: z.record(z.string(), schemas.approval),
})

export class MockClient implements StatePortClient {
  readonly adapter = 'mock' as const

  private readonly captureMode: boolean
  private db: MockDatabase
  private tick: () => number
  private terminalSessions = new Map<string, TerminalSession>()
  private terminalListeners = new Map<string, Set<(e: TerminalSessionEvent) => void>>()
  private terminalInputBuffers = new Map<string, string>()
  private extras: ScenarioExtras = EMPTY_EXTRAS
  /** Settings optimistic-concurrency history (scope → revision + snapshots). */
  private settingsRevisions = new Map<string, number>()
  private settingsHistory: {
    scope: string
    revision: number
    receiptId: string
    before: unknown
    action?: 'settings.patch' | 'settings.rollback'
    createdAt?: string
    changes?: Record<string, SettingsScalar>
    previousValues?: Record<string, SettingsScalar>
  }[] = []
  /** Governed execution runs (in-memory; deterministic). */
  private runRecords = new Map<string, RunRecord>()
  private runSeq = 0
  /** Context lifecycle per instance (in-memory). */
  private contextLifecycles = new Map<string, ContextLifecycle>()
  /** Exact mock read/list observations required by governed file mutations. */
  private fileTreeBases = new Set<string>()
  private fileReadRevisions = new Map<string, string>()

  constructor(options: { captureMode?: boolean } = {}) {
    this.captureMode = options.captureMode ?? isStudyStateCaptureRequested()
    this.tick = prng(0x5eed)
    this.db = this.load()
  }

  private nowMs(): number {
    return this.captureMode ? STUDYSTATE_CAPTURE_NOW_MS : Date.now()
  }

  private clockIso(): string {
    return new Date(this.nowMs()).toISOString()
  }

  private isStudyStateCapture(instanceId: string): boolean {
    return this.captureMode && instanceId === INSTANCE_IDS.studyAlpha
  }

  private nextConversationMessageId(instanceId: string, role: 'user' | 'assistant'): string {
    if (this.isStudyStateCapture(instanceId)) {
      return nextId(this.db, role === 'user' ? 'msg_capture_study_user' : 'msg_capture_study_assistant')
    }
    return nextId(this.db, 'msg')
  }

  // ── persistence ────────────────────────────────────────────────────────────

  private load(): MockDatabase {
    if (this.captureMode) {
      const seed = buildSeed(this.nowMs())
      saveMockEnvelope(seed, this.nowMs())
      return seed
    }
    const envelope = loadMockEnvelope()
    if (envelope) {
      const parsed = dbSchema.safeParse(envelope.data)
      if (parsed.success) return envelope.data as MockDatabase
      // Corrupt or outdated payload: fall through to a fresh deterministic seed.
    }
    const seed = buildSeed()
    saveMockEnvelope(seed)
    return seed
  }

  private persist(): void {
    saveMockEnvelope(this.db, this.nowMs())
  }

  /** Force the debounced write to land before an authority-critical response resolves. */
  flush(): void {
    flushMockWrites(this.db, this.nowMs())
  }

  // ── latency + failure guards ────────────────────────────────────────────────

  private async lat(kind?: 'conversation_load'): Promise<void> {
    const behavior = getActiveBehavior()
    let ms = 80 + Math.round(this.tick() * 170)
    if (kind === 'conversation_load') ms = 3200
    const mult = behavior?.latencyMultiplier ?? 1
    await sleep(ms * mult)
  }

  private guard(): void {
    const behavior = getActiveBehavior()
    if (behavior?.failRequests) {
      throw new ClientError('http', behavior.failRequests.message, {
        status: behavior.failRequests.status,
        detail: 'Injected by the active scenario.',
      })
    }
    if (behavior?.serviceState === 'offline') {
      throw new ClientError('network', 'Local service is unreachable', {
        detail: 'The active scenario forces the service offline.',
      })
    }
  }

  // ── shared factories ───────────────────────────────────────────────────────

  private makeReceipt(input: {
    instanceId: string
    actionName: string
    eventKind: string
    actor?: Receipt['actor']
    result?: Receipt['result']
    summary: string
    diff?: FileDiff
    expectedRevision?: string
    resultRevision?: string
    planDigest?: Receipt['planDigest']
    relatedApprovalId?: string
    relatedPlanId?: string
    relatedOperationId?: string
    relatedConversationId?: string
    beforeSummary?: string
    afterSummary?: string
  }): Receipt {
    const id = nextId(this.db, 'rcpt')
    const instance = this.db.instances.find((i) => i.id === input.instanceId)
    const createdAt = this.clockIso()
    const raw = {
      id,
      event: input.eventKind,
      instance: input.instanceId,
      actor: input.actor ?? 'user',
      result: input.result ?? 'validated',
      at: createdAt,
      expectedRevision: input.expectedRevision,
      resultRevision: input.resultRevision,
      planDigest: input.planDigest,
      payloadDigest: fakeDigest(`${id}:${input.eventKind}`),
    }
    const receipt: Receipt = {
      id,
      instanceId: input.instanceId,
      packageId: instance?.packageId ?? 'pkg_unknown',
      actionName: input.actionName,
      eventKind: input.eventKind,
      actor: input.actor ?? 'user',
      result: input.result ?? 'validated',
      createdAt,
      expectedRevision: input.expectedRevision,
      resultRevision: input.resultRevision,
      planDigest: input.planDigest,
      payloadDigest: fakeDigest(`${id}:${input.eventKind}`),
      validation: { state: 'validated', detail: 'Response matched the expected revision.' },
      summary: input.summary,
      beforeSummary: input.beforeSummary,
      afterSummary: input.afterSummary,
      diff: input.diff,
      relatedApprovalId: input.relatedApprovalId,
      relatedPlanId: input.relatedPlanId,
      relatedOperationId: input.relatedOperationId,
      relatedConversationId: input.relatedConversationId,
      rawJson: JSON.stringify(raw, null, 2),
    }
    this.db.receipts[id] = receipt
    if (instance) instance.receiptIds.unshift(id)
    this.addActivity({
      instanceId: input.instanceId,
      kind: input.eventKind,
      title: input.actionName,
      createdAt,
      relatedReceiptId: id,
    })
    return receipt
  }

  private addActivity(input: {
    instanceId?: string
    kind: string
    title: string
    detail?: string
    createdAt?: string
    relatedReceiptId?: string
    route?: string
  }): void {
    this.db.activity.unshift({
      id: nextId(this.db, 'act'),
      instanceId: input.instanceId,
      kind: input.kind,
      title: input.title,
      detail: input.detail,
      createdAt: input.createdAt ?? nowIso(),
      read: false,
      relatedReceiptId: input.relatedReceiptId,
      route: input.route,
    })
    const inst = this.db.instances.find((i) => i.id === input.instanceId)
    if (inst) {
      inst.recentActivity = this.db.activity.filter((a) => a.instanceId === inst.id).slice(0, 5)
    }
  }

  private requireInstance(instanceId: string): ApplicationInstance {
    const inst = this.db.instances.find((i) => i.id === instanceId)
    if (!inst) {
      throw new ClientError('http', `Application not found: ${instanceId}`, { status: 404 })
    }
    return inst
  }

  private requireConversation(instance: ApplicationInstance): Conversation {
    if (!instance.conversationId) {
      throw new ClientError('validation', `Application ${instance.id} has no conversation identity`, {
        detail: 'The mock never synthesizes an operational conversation identity from an application instance id.',
      })
    }
    const conversation = this.db.conversations[instance.conversationId]
    if (!conversation) {
      throw new ClientError('http', 'Conversation not found', { status: 404 })
    }
    return conversation
  }

  // ── settings revision helpers (optimistic concurrency, mirrors the contract) ─

  private bumpSettingsRevision(
    scope: string,
    receiptId: string,
    before: unknown,
    details?: {
      action: 'settings.patch' | 'settings.rollback'
      createdAt: string
      changes: Record<string, SettingsScalar>
      previousValues: Record<string, SettingsScalar>
    },
  ): void {
    const next = (this.settingsRevisions.get(scope) ?? 0) + 1
    this.settingsRevisions.set(scope, next)
    this.settingsHistory.push({ scope, revision: next, receiptId, before, ...details })
  }

  private recordSettingsMutation(scope: string, instanceId: string, actionName: string, before: unknown): void {
    const receipt = this.makeReceipt({
      instanceId,
      actionName,
      eventKind: 'settings.update',
      summary: `${actionName}.`,
    })
    this.bumpSettingsRevision(scope, receipt.id, before)
  }

  private recordGlobalSettingsMutation(
    before: GlobalSettings,
    after: GlobalSettings,
    actionName: string,
  ): void {
    const { changes, previousValues } = changedGlobalServiceValues(before, after)
    if (Object.keys(changes).length === 0) return
    const receipt = this.makeReceipt({
      instanceId: '',
      actionName,
      eventKind: 'settings.update',
      summary: `${actionName}.`,
    })
    this.bumpSettingsRevision('global', receipt.id, before, {
      action: 'settings.patch',
      createdAt: receipt.createdAt,
      changes,
      previousValues,
    })
  }

  private rollbackGlobalSettings(
    input: { expectedRevision: number; receiptId: string },
    current: GlobalSettings,
  ): GlobalSettings {
    const currentRevision = this.settingsRevisions.get('global') ?? 0
    if (input.expectedRevision !== currentRevision) {
      throw new ClientError('http', 'Settings changed since you loaded them — reload and try again', { status: 409 })
    }
    const entry = this.settingsHistory.find(
      (candidate) =>
        candidate.scope === 'global' &&
        candidate.receiptId === input.receiptId &&
        candidate.previousValues,
    )
    if (!entry?.previousValues) {
      throw new ClientError('http', `Settings receipt not found: ${input.receiptId}`, { status: 404 })
    }
    const beforeRollback = Object.fromEntries(
      Object.keys(entry.previousValues).map((key) => [
        key,
        globalServiceValues(current)[key] ?? entry.changes?.[key],
      ]),
    ) as Record<string, SettingsScalar>
    const restored = applyGlobalServiceValues(current, entry.previousValues)
    const receipt = this.makeReceipt({
      instanceId: '',
      actionName: 'Settings rolled back',
      eventKind: 'settings.rollback',
      summary: 'Backend-owned settings were restored to the state captured before the referenced change.',
    })
    this.bumpSettingsRevision('global', receipt.id, current, {
      action: 'settings.rollback',
      createdAt: receipt.createdAt,
      changes: { ...entry.previousValues },
      previousValues: beforeRollback,
    })
    return restored
  }

  private rollbackSettings<T>(scope: string, input: { expectedRevision: number; receiptId: string }, current: T): T {
    const currentRevision = this.settingsRevisions.get(scope) ?? 0
    if (input.expectedRevision !== currentRevision) {
      throw new ClientError('http', 'Settings changed since you loaded them — reload and try again', { status: 409 })
    }
    const entry = this.settingsHistory.find((e) => e.scope === scope && e.receiptId === input.receiptId)
    if (!entry) {
      throw new ClientError('http', `Settings receipt not found: ${input.receiptId}`, { status: 404 })
    }
    const receipt = this.makeReceipt({
      instanceId: scope === 'global' ? '' : scope.slice('app:'.length),
      actionName: 'Settings rolled back',
      eventKind: 'settings.rollback',
      summary: 'Settings restored to the state captured before the referenced change.',
    })
    this.bumpSettingsRevision(scope, receipt.id, current)
    return entry.before as T
  }

  // ── scenario extras ─────────────────────────────────────────────────────────

  private refreshExtras(): ScenarioExtras {
    const behavior = getActiveBehavior()
    const key = JSON.stringify({
      p: behavior?.infraPlan,
      o: behavior?.orchestration,
      a: behavior?.authorization,
    })
    if (this.extras.key === key) return this.extras
    const extras: ScenarioExtras = emptyExtras(key)
    const now = this.nowMs()

    if (behavior?.infraPlan) {
      const stateMap: Record<string, InfrastructurePlan['state']> = {
        prepared: 'prepared',
        awaiting_approval: 'awaiting_approval',
        running: 'running',
        failed: 'failed',
      }
      const plan: InfrastructurePlan = {
        id: 'plan_scn_0001',
        instanceId: INSTANCE_IDS.nixosInfra,
        targetId: TARGET_IDS.nixosVm,
        operation: 'start',
        title: 'Start virtual machine',
        state: stateMap[behavior.infraPlan] ?? 'prepared',
        risk: 'medium',
        requiresApproval: true,
        coveredByAuthorization: false,
        steps: [
          { id: 'ps_s1', title: 'Verify target identity', detail: 'stateport target verify homelab-dev', kind: 'check' },
          { id: 'ps_s2', title: 'Start the virtual machine', detail: 'stateport vm start homelab-dev', kind: 'command' },
          { id: 'ps_s3', title: 'Wait for SSH', detail: 'stateport ssh wait --timeout 120s', kind: 'command' },
        ],
        digest: fakeDigest('plan:plan_scn_0001'),
        beforeSummary: 'Virtual machine homelab-dev is stopped.',
        afterSummary: 'Virtual machine homelab-dev is running; SSH becomes ready.',
        rollbackNotes: 'Stop the virtual machine from Deployments.',
        createdAt: new Date(now - 10 * 60_000).toISOString(),
      }
      if (behavior.infraPlan === 'awaiting_approval') {
        const approval: Approval = {
          id: 'appr_scn_0001',
          instanceId: INSTANCE_IDS.nixosInfra,
          kind: 'infrastructure_plan',
          title: 'Start virtual machine',
          operationType: 'Infrastructure · VM start',
          risk: 'medium',
          status: 'pending',
          scope: ['Target: homelab-dev (local virtual machine)', 'Operation: start'],
          beforeSummary: plan.beforeSummary,
          afterSummary: plan.afterSummary,
          planDigest: plan.digest,
          planId: plan.id,
          targetId: TARGET_IDS.nixosVm,
          whyRequired: 'Starting infrastructure changes what is running on this machine.',
          requestedAt: new Date(now - 10 * 60_000).toISOString(),
          expiresAt: new Date(now + 6 * 3_600_000).toISOString(),
          decision: {
            kind: 'infrastructure_plan',
            expectedInstanceId: INSTANCE_IDS.nixosInfra,
            expectedDigest: plan.digest.value,
          },
          currentDigest: plan.digest,
        }
        plan.approvalId = approval.id
        extras.approvals.push(approval)
      }
      if (behavior.infraPlan === 'running') {
        extras.operations.push({
          id: 'op_scn_0001',
          instanceId: INSTANCE_IDS.nixosInfra,
          kind: 'infrastructure_plan',
          title: 'Start virtual machine',
          state: 'running',
          stageLabel: 'Waiting for SSH',
          progressPercent: 55,
          startedAt: new Date(now - 90_000).toISOString(),
          updatedAt: new Date(now - 5_000).toISOString(),
          canPause: false,
          canCancel: true,
          log: [
            '$ stateport vm start homelab-dev',
            'vm homelab-dev: power state starting',
            'waiting for ssh on 127.0.0.1:2222 …',
          ],
          relatedPlanId: plan.id,
        })
      }
      extras.plans.push(plan)
    }

    if (
      behavior?.orchestration &&
      behavior.orchestration !== 'unavailable' &&
      behavior.orchestration !== 'backend_unavailable'
    ) {
      const stageMap: Record<string, OrchestrationSession['stage']> = {
        proposal_ready: 'review_base',
        approved: 'run',
        running: 'run',
        awaiting_review: 'review_result',
        closed: 'receipt',
      }
      const stateMap: Record<string, OrchestrationSession['state']> = {
        proposal_ready: 'prepared',
        approved: 'approved',
        running: 'running',
        awaiting_review: 'applied',
        closed: 'human_accepted',
      }
      extras.orchestration[INSTANCE_IDS.nixosInfra] = {
        id: 'orch_scn_0001',
        instanceId: INSTANCE_IDS.nixosInfra,
        objective: 'Add a health-check endpoint to the nginx service and validate the flake',
        mode: 'assisted',
        stage: stageMap[behavior.orchestration] ?? 'review_base',
        state: stateMap[behavior.orchestration] ?? 'prepared',
        baseIdentity: {
          name: 'nixos-homelab',
          branch: 'main',
          revision: 'a1b2c3d4e5',
          clean: true,
        },
        scope: ['modules/services.nix', 'hosts/homelab/configuration.nix'],
        permissions: ['Edit files inside nixos-homelab', 'Run nix flake check'],
        budget: { maxOperations: 6, maxMinutes: 30, usedOperations: 2, usedMinutes: 7 },
        implementer: 'Assistant (orchestration)',
        reviewer: 'You',
        resultSummary:
          behavior.orchestration === 'awaiting_review' || behavior.orchestration === 'closed'
            ? 'Health endpoint added; nix flake check passed.'
            : undefined,
        createdAt: new Date(now - 40 * 60_000).toISOString(),
        updatedAt: new Date(now - 5 * 60_000).toISOString(),
      }
    }

    if (behavior?.authorization) {
      extras.authorizations[INSTANCE_IDS.nixosInfra] = {
        id: 'authz_scn_0001',
        instanceId: INSTANCE_IDS.nixosInfra,
        targetId: TARGET_IDS.nixosVm,
        status: behavior.authorization === 'active' ? 'active' : 'proposed',
        covers: ['observe', 'validate', 'health_check', 'start', 'stop', 'restart'],
        doesNotCover: [
          'Destroy the virtual machine',
          'Change target identity',
          'Change network scope',
          'Expand filesystem scope',
          'Broaden terminal access',
          'Run an unreviewed arbitrary command',
        ],
        createdAt: new Date(now - 2 * 3_600_000).toISOString(),
        expiresAt: new Date(now + 22 * 3_600_000).toISOString(),
        createdByReceiptId: behavior.authorization === 'active' ? 'rcpt_0007' : undefined,
      }
    }

    this.extras = extras
    return extras
  }

  // ── session ─────────────────────────────────────────────────────────────────

  session: StatePortClient['session'] = {
    getSession: async (): Promise<SessionInfo> => {
      await this.lat()
      this.guard()
      return {
        authenticated: true,
        user: { id: 'usr_local', displayName: 'Local user' },
        issuedAt: nowIso(),
      }
    },
    getLocalServiceStatus: async (): Promise<LocalServiceStatus> => {
      await this.lat()
      const behavior = getActiveBehavior()
      const state = behavior?.serviceState ?? 'connected'
      return {
        state,
        endpoint: this.db.globalSettings.advanced.localServiceEndpoint,
        version: state === 'offline' ? undefined : '0.1.0',
        lastContactAt: state === 'offline' ? new Date(Date.now() - 5 * 60_000).toISOString() : nowIso(),
        detail:
          state === 'offline'
            ? 'The local service did not answer the last health probe.'
            : state === 'degraded'
              ? 'The local service answers slowly.'
              : undefined,
        actor: {
          role: 'local_user',
          actorId: 'usr_local',
          platformOperationsAllowed: false,
          statebenchInspectionAllowed: false,
        },
      }
    },
    getBuildInfo: async (): Promise<BuildInfo> => {
      await this.lat()
      return {
        version: '0.1.0',
        commit: 'dev-mock',
        builtAt: nowIso(),
        adapter: 'mock',
        mode: import.meta.env.DEV ? 'development' : 'production',
      }
    },
    reconnect: async (): Promise<LocalServiceStatus> => {
      await this.lat()
      const behavior = getActiveBehavior()
      const state = behavior?.serviceState ?? 'connected'
      if (state === 'offline') {
        throw new ClientError('network', 'Local service is unreachable', {
          detail: 'Retry failed. Check that the StatePort service is running.',
        })
      }
      return {
        state,
        endpoint: this.db.globalSettings.advanced.localServiceEndpoint,
        version: '0.1.0',
        lastContactAt: nowIso(),
        actor: {
          role: 'local_user',
          actorId: 'usr_local',
          platformOperationsAllowed: false,
          statebenchInspectionAllowed: false,
        },
      }
    },
  }

  // ── applications ─────────────────────────────────────────────────────────────

  applications: StatePortClient['applications'] = {
    canRename: true,
    list: async (): Promise<ApplicationInstance[]> => {
      await this.lat()
      this.guard()
      const behavior = getActiveBehavior()
      if (behavior?.hideApplications) return []
      let instances = this.db.instances
      if (behavior?.degradeInstances) {
        instances = instances.map((i) => ({
          ...i,
          health: 'degraded' as const,
        }))
      }
      return instances.map((i) => schemas.applicationInstance.parse(i))
    },
    get: async (instanceId) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      return schemas.applicationInstance.parse(inst)
    },
    rename: async (instanceId, name) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      inst.name = name.trim() || inst.name
      this.persist()
      return schemas.applicationInstance.parse(inst)
    },
    setPinned: async (instanceId, pinned) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      inst.pinned = pinned
      this.persist()
      return schemas.applicationInstance.parse(inst)
    },
    touchOpened: async (instanceId) => {
      const inst = this.requireInstance(instanceId)
      inst.lastOpenedAt = nowIso()
      this.persist()
    },
  }

  // ── catalog ──────────────────────────────────────────────────────────────────

  catalog: StatePortClient['catalog'] = {
    list: async (): Promise<CatalogPackage[]> => {
      await this.lat()
      this.guard()
      return this.db.packages.map((pkg) => ({
        pkg,
        installedInstanceCount: this.db.instances.filter((i) => i.packageId === pkg.id).length,
        installRequiresApproval: false,
        updateAvailable:
          pkg.id === 'pkg_checklist_state'
            ? { fromVersion: '1.0.0', toVersion: '1.1.0', releaseNotes: 'Adds per-item notes and a progress summary.' }
            : undefined,
      }))
    },
    get: async (packageId) => {
      await this.lat()
      this.guard()
      const pkg = this.db.packages.find((p) => p.id === packageId)
      if (!pkg) throw new ClientError('http', `Package not found: ${packageId}`, { status: 404 })
      return {
        pkg,
        installedInstanceCount: this.db.instances.filter((i) => i.packageId === pkg.id).length,
        installRequiresApproval: false,
      }
    },
    createInstance: async (packageId, input) => {
      await this.lat()
      this.guard()
      const pkg = this.db.packages.find((p) => p.id === packageId)
      if (!pkg) throw new ClientError('http', `Package not found: ${packageId}`, { status: 404 })
      const id = nextId(this.db, 'ins')
      const conversationId = nextId(this.db, 'conv')
      const instance: ApplicationInstance = {
        id,
        name: input.name.trim() || `New ${pkg.displayName}`,
        packageId: pkg.id,
        packageName: pkg.name,
        packageDisplayName: pkg.displayName,
        health: 'ready',
        attention: [],
        recentActivity: [],
        settings: {
          instanceId: id,
          notificationLevel: 'inherit',
          conversation: { defaultContext: ['application', 'summary'] },
          backup: { enabled: true, intervalHours: 24 },
          terminal: {},
        },
        conversationId,
        capabilities: pkg.capabilities.map((cid) => ({ id: cid, status: 'available' as const })),
        receiptIds: [],
        recovery: { state: 'not_configured' },
        pinned: false,
        createdAt: nowIso(),
      }
      if (pkg.name === 'study-state') {
        instance.packageState = {
          kind: 'study-state',
          goal: 'Set a first learning goal',
          goalProgressPercent: 0,
          activities: [],
          evidence: [],
        }
      }
      if (pkg.name === 'checklist-state') {
        instance.packageState = { kind: 'checklist-state', items: [] }
      }
      this.db.instances.push(instance)
      this.db.conversations[conversationId] = {
        id: conversationId,
        instanceId: id,
        title: 'Conversation',
        channel: 'web',
        deliveryState: 'delivered',
        retentionNote: 'History is kept on this machine until you clear it.',
        messages: [],
        createdAt: nowIso(),
        updatedAt: nowIso(),
      }
      this.db.files[id] = {}
      const receipt = this.makeReceipt({
        instanceId: id,
        actionName: `${pkg.displayName} installed`,
        eventKind: 'application.install.fixture',
        result: 'applied',
        summary: `${instance.name} was installed from the reviewed ${pkg.displayName} package.`,
      })
      this.persist()
      return {
        instance: schemas.applicationInstance.parse(instance),
        receipt: {
          id: receipt.id,
          digest: receipt.payloadDigest ?? fakeDigest(receipt.id),
        },
      }
    },
    refresh: async (): Promise<void> => {
      await this.lat()
      this.guard()
      // The mock catalog is seeded and deterministic; a refresh is an honest
      // no-op re-scan that records activity.
      this.addActivity({ kind: 'catalog.refresh', title: 'Catalog refreshed' })
    },
  }

  // ── canonical sources ───────────────────────────────────────────────────────

  sources: StatePortClient['sources'] = {
    list: async () => {
      await this.lat()
      this.guard()
      return [{ ...MOCK_PUBLIC_SOURCE, productionAction: { ...MOCK_PUBLIC_SOURCE.productionAction } }]
    },
    getOperatorDetail: async (sourceId) => {
      await this.lat()
      this.guard()
      if (sourceId !== MOCK_SOURCE_ID) {
        throw new ClientError('http', 'Application source was not found', {
          status: 404,
          code: 'source_not_found',
        })
      }
      return structuredClone(MOCK_OPERATOR_SOURCE)
    },
    verifyDevelopmentCandidate: async (input): Promise<DevelopmentSourceResolution> => {
      await this.lat()
      this.guard()
      const candidate = MOCK_OPERATOR_SOURCE.developmentCandidate
      if (
        !candidate ||
        input.sourceId !== MOCK_SOURCE_ID ||
        input.sourceClass !== candidate.sourceClass ||
        input.expectedCommit !== candidate.identity.commit ||
        input.expectedTree !== candidate.identity.tree ||
        input.expectedManifestDigest !== candidate.identity.manifestDigest ||
        input.expectedSourceDigest !== candidate.identity.sourceDigest ||
        input.acknowledgement !== candidate.verificationAction.acknowledgement
      ) {
        throw new ClientError('http', 'Development source identity changed; inspect it again', {
          status: 409,
          code: 'source_candidate_stale',
        })
      }
      return {
        formatVersion: 'stateport.development-source-resolution/v1',
        sourceId: MOCK_SOURCE_ID,
        applicationId: MOCK_OPERATOR_SOURCE.application.id,
        sourceClass: 'development_candidate',
        identity: { ...candidate.identity },
        releaseStatus: 'candidate',
        trust: 'development_only',
        productionInstallAllowed: false,
        verifiedModules: [...candidate.verifiedModules],
        requiredSelfTests: [...candidate.verifiedSelfTests],
        selfTestDeclarationsMatched: true,
        selfTestsExecutedByThisOperation: false,
        verifiedAt: nowIso(),
        receiptDigest: `sha256:${'b'.repeat(64)}`,
      }
    },
  }

  platformStateBench: StatePortClient['platformStateBench'] = {
    getMatrix: async (status) => {
      if (!canInspectPlatformStateBench(status)) {
        throw new ClientError('unavailable', 'Platform StateBench evidence requires operator access', {
          detail: 'The operator-only endpoint was not requested.',
        })
      }
      await this.lat()
      throw new ClientError('unavailable', 'Platform StateBench evidence is not simulated', {
        detail: 'Use the connected operator service to inspect verified RunBundles.',
      })
    },
  }

  // ── settings ─────────────────────────────────────────────────────────────────

  globalSettings: StatePortClient['globalSettings'] = {
    get: async (): Promise<GlobalSettings> => {
      await this.lat()
      this.guard()
      return schemas.globalSettings.parse(this.db.globalSettings)
    },
    getRollbackHistory: async (): Promise<GlobalSettingsRollbackHistory> => {
      await this.lat()
      this.guard()
      const targets: GlobalSettingsRollbackTarget[] = this.settingsHistory
        .filter(
          (entry) =>
            entry.scope === 'global' &&
            entry.action !== undefined &&
            entry.createdAt !== undefined &&
            entry.changes !== undefined &&
            entry.previousValues !== undefined,
        )
        .slice(-10)
        .reverse()
        .map((entry) => ({
          receiptId: entry.receiptId,
          revision: entry.revision,
          action: entry.action!,
          createdAt: entry.createdAt!,
          changes: { ...entry.changes! },
          previousValues: { ...entry.previousValues! },
        }))
      return {
        currentRevision: this.settingsRevisions.get('global') ?? 0,
        targets,
      }
    },
    update: async (patch) => {
      await this.lat()
      this.guard()
      const before = this.db.globalSettings
      this.db.globalSettings = deepMerge(this.db.globalSettings, patch)
      this.recordGlobalSettingsMutation(before, this.db.globalSettings, 'Global settings updated')
      this.persist()
      return schemas.globalSettings.parse(this.db.globalSettings)
    },
    rollback: async (input) => {
      await this.lat()
      this.guard()
      this.db.globalSettings = this.rollbackGlobalSettings(input, this.db.globalSettings)
      this.persist()
      return schemas.globalSettings.parse(this.db.globalSettings)
    },
    reset: async () => {
      await this.lat()
      this.guard()
      const before = this.db.globalSettings
      this.db.globalSettings = defaultGlobalSettings()
      this.recordGlobalSettingsMutation(before, this.db.globalSettings, 'Global settings reset')
      this.persist()
      return schemas.globalSettings.parse(this.db.globalSettings)
    },
    exportJson: async () => {
      await this.lat()
      this.guard()
      return JSON.stringify(this.db.globalSettings, null, 2)
    },
    importJson: async (json) => {
      await this.lat()
      this.guard()
      assertSettingsImportSize(json)
      let parsed: unknown
      try {
        parsed = JSON.parse(json)
      } catch {
        throw new ClientError('validation', 'Settings import is not valid JSON')
      }
      const result = schemas.globalSettings.safeParse(parsed)
      if (!result.success) {
        throw new ClientError('validation', 'Settings import failed validation', {
          detail: result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n'),
        })
      }
      const before = this.db.globalSettings
      this.db.globalSettings = result.data
      this.recordGlobalSettingsMutation(before, this.db.globalSettings, 'Global settings imported')
      this.persist()
      return result.data
    },
  }

  appSettings: StatePortClient['appSettings'] = {
    get: async (instanceId): Promise<AppSettings> => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      return schemas.appSettings.parse(inst.settings)
    },
    update: async (instanceId, patch) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      const before = inst.settings
      inst.settings = deepMerge(inst.settings, patch)
      inst.settings.instanceId = instanceId
      this.recordSettingsMutation(`app:${instanceId}`, instanceId, 'Application settings updated', before)
      this.persist()
      return schemas.appSettings.parse(inst.settings)
    },
    rollback: async (instanceId, input) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      inst.settings = this.rollbackSettings(`app:${instanceId}`, input, inst.settings)
      this.persist()
      return schemas.appSettings.parse(inst.settings)
    },
    reset: async (instanceId) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      const before = inst.settings
      inst.settings = {
        instanceId,
        notificationLevel: 'inherit',
        conversation: { defaultContext: ['application', 'summary'] },
        backup: { enabled: true, intervalHours: 24 },
        terminal: {},
      }
      this.recordSettingsMutation(`app:${instanceId}`, instanceId, 'Application settings reset', before)
      this.persist()
      return schemas.appSettings.parse(inst.settings)
    },
  }

  // ── activity / attention / notifications ─────────────────────────────────────

  activity: StatePortClient['activity'] = {
    listActivity: async (filter?: ActivityFilter): Promise<ActivityItem[]> => {
      await this.lat()
      this.guard()
      let items = this.db.activity
      if (filter?.instanceId) items = items.filter((a) => a.instanceId === filter.instanceId)
      if (filter?.unreadOnly) items = items.filter((a) => !a.read)
      if (filter?.limit) items = items.slice(0, filter.limit)
      return items
    },
    markActivityRead: async (activityId) => {
      await this.lat()
      this.guard()
      const item = this.db.activity.find((a) => a.id === activityId)
      if (item) {
        item.read = true
        this.persist()
      }
    },
    listAttention: async (instanceId?: string): Promise<AttentionItem[]> => {
      await this.lat()
      this.guard()
      const items = this.db.instances.flatMap((i) => i.attention)
      return instanceId ? items.filter((a) => a.instanceId === instanceId) : items
    },
    acknowledgeAttention: async (attentionId) => {
      await this.lat()
      this.guard()
      for (const inst of this.db.instances) {
        const item = inst.attention.find((a) => a.id === attentionId)
        if (item) {
          item.read = true
          item.acknowledged = true
          if (item.severity !== 'urgent') {
            inst.attention = inst.attention.filter((a) => a.id !== attentionId)
          }
          if (inst.attention.filter((a) => !a.acknowledged).length === 0 && inst.health === 'attention_needed') {
            inst.health = 'ready'
          }
          this.makeReceipt({
            instanceId: item.instanceId,
            actionName: 'Attention item marked read',
            eventKind: 'attention.read',
            summary: `“${item.title}” marked read.`,
          })
          this.persist()
          return item
        }
      }
      throw new ClientError('http', `Attention item not found: ${attentionId}`, { status: 404 })
    },
    listNotifications: async (): Promise<NotificationItem[]> => {
      await this.lat()
      this.guard()
      return this.db.notifications
    },
    markNotificationRead: async (notificationId) => {
      await this.lat()
      this.guard()
      const item = this.db.notifications.find((n) => n.id === notificationId)
      if (item) {
        item.read = true
        this.persist()
      }
    },
    snoozeNotification: async (notificationId, until) => {
      await this.lat()
      this.guard()
      const item = this.db.notifications.find((n) => n.id === notificationId)
      if (item) {
        item.snoozedUntil = until
        this.persist()
      }
    },
  }

  // ── approvals ────────────────────────────────────────────────────────────────

  approvals: StatePortClient['approvals'] = {
    list: async (filter?: ApprovalFilter): Promise<Approval[]> => {
      await this.lat()
      this.guard()
      const behavior = getActiveBehavior()
      const extras = this.refreshExtras()
      let items: Approval[] = [...Object.values(this.db.approvals), ...extras.approvals]
      if (behavior?.approvals === 'empty') items = []
      if (behavior?.approvals === 'stale') {
        items = items.map((a) =>
          a.status === 'pending'
            ? { ...a, currentDigest: fakeDigest(`stale:${a.id}`) }
            : a,
        )
      }
      if (filter?.instanceId) items = items.filter((a) => a.instanceId === filter.instanceId)
      if (filter?.status) items = items.filter((a) => a.status === filter.status)
      if (filter?.risk) items = items.filter((a) => a.risk === filter.risk)
      if (filter?.query) {
        const q = filter.query.toLowerCase()
        items = items.filter(
          (a) => a.title.toLowerCase().includes(q) || a.operationType.toLowerCase().includes(q),
        )
      }
      return items.sort((a, b) => b.requestedAt.localeCompare(a.requestedAt))
    },
    get: async (approvalId) => {
      await this.lat()
      this.guard()
      const extras = this.refreshExtras()
      const approval = this.db.approvals[approvalId] ?? extras.approvals.find((a) => a.id === approvalId)
      if (!approval) throw new ClientError('http', `Approval not found: ${approvalId}`, { status: 404 })
      const behavior = getActiveBehavior()
      if (behavior?.approvals === 'stale' && approval.status === 'pending') {
        return { ...approval, currentDigest: fakeDigest(`stale:${approval.id}`) }
      }
      return approval
    },
    approve: async (approvalId, input) => {
      await this.lat()
      this.guard()
      const extras = this.refreshExtras()
      const fromExtras = extras.approvals.find((a) => a.id === approvalId)
      const approval = this.db.approvals[approvalId] ?? fromExtras
      if (!approval) throw new ClientError('http', `Approval not found: ${approvalId}`, { status: 404 })
      if (approval.status !== 'pending') {
        throw new ClientError('http', `Approval is already ${approval.status}`, { status: 409 })
      }
      const templateKind: boolean = approval.kind === 'template_upgrade'
      const templateDecision: boolean = approval.decision.kind === 'template_upgrade'
      if (
        templateKind !== templateDecision ||
        ((templateKind || templateDecision) && !approval.targetId)
      ) {
        throw new ClientError('validation', 'Template upgrade approval identity is incomplete')
      }
      if (approval.expiresAt && new Date(approval.expiresAt).getTime() < Date.now()) {
        approval.status = 'expired'
        this.persist()
        throw new ClientError('http', 'Approval has expired', { status: 410 })
      }
      // Stale detection: the caller must prove it reviewed the current digest,
      // and the plan must not have moved since the approval was requested.
      const behavior = getActiveBehavior()
      const currentDigest =
        behavior?.approvals === 'stale' ? fakeDigest(`stale:${approval.id}`) : (approval.currentDigest ?? approval.planDigest)
      if (currentDigest.value !== approval.planDigest.value) {
        throw new ClientError('http', 'This approval is stale — the underlying state changed since it was requested', {
          status: 409,
          detail: 'Revalidate the plan before approving.',
        })
      }
      if (input.expectedDigest !== approval.planDigest.value) {
        throw new ClientError('http', 'Digest mismatch — revalidate before approving', { status: 409 })
      }
      approval.status = 'approved'
      approval.decidedAt = nowIso()
      if (fromExtras) {
        // A decision on a scenario-materialized approval becomes real state.
        this.db.approvals[approval.id] = approval
      }
      const plan = this.db.plans[approval.planId ?? ''] ?? extras.plans.find((p) => p.id === approval.planId)
      if (plan) {
        plan.state = 'approved'
        if (!this.db.plans[plan.id]) this.db.plans[plan.id] = plan
      }
      const receipt = this.makeReceipt({
        instanceId: approval.instanceId,
        actionName: receiptNameForApproval(approval, 'approved'),
        eventKind: 'approval.approve',
        summary: `${approval.title} was approved.`,
        planDigest: approval.planDigest,
        relatedApprovalId: approval.id,
        relatedPlanId: approval.planId,
        beforeSummary: approval.beforeSummary,
        afterSummary: approval.afterSummary,
      })
      approval.resultingReceiptId = receipt.id
      this.persist()
      // Approval decisions are durable authority, not disposable UI state.
      // Resolve only after the linked approval, plan, and receipt can survive
      // an immediate navigation/reload.
      this.flush()
      return { approval, receipt }
    },
    reject: async (approvalId, input) => {
      await this.lat()
      this.guard()
      const extras = this.refreshExtras()
      const fromExtras = extras.approvals.find((a) => a.id === approvalId)
      const approval = this.db.approvals[approvalId] ?? fromExtras
      if (!approval) throw new ClientError('http', `Approval not found: ${approvalId}`, { status: 404 })
      if (approval.status !== 'pending') {
        throw new ClientError('http', `Approval is already ${approval.status}`, { status: 409 })
      }
      const templateKind: boolean = approval.kind === 'template_upgrade'
      const templateDecision: boolean = approval.decision.kind === 'template_upgrade'
      if (
        templateKind !== templateDecision ||
        ((templateKind || templateDecision) && !approval.targetId)
      ) {
        throw new ClientError('validation', 'Template upgrade approval identity is incomplete')
      }
      approval.status = 'rejected'
      approval.decidedAt = nowIso()
      approval.decisionReason = input.reason
      if (fromExtras) this.db.approvals[approval.id] = approval
      const plan = this.db.plans[approval.planId ?? '']
      if (plan) plan.state = 'rejected'
      const receipt = this.makeReceipt({
        instanceId: approval.instanceId,
        actionName: receiptNameForApproval(approval, 'rejected'),
        eventKind: 'approval.reject',
        result: 'rejected',
        summary: `${approval.title} was rejected${input.reason ? `: ${input.reason}` : '.'}`,
        planDigest: approval.planDigest,
        relatedApprovalId: approval.id,
        relatedPlanId: approval.planId,
      })
      approval.resultingReceiptId = receipt.id
      this.persist()
      this.flush()
      return { approval, receipt }
    },
  }

  // ── receipts ─────────────────────────────────────────────────────────────────

  receipts: StatePortClient['receipts'] = {
    list: async (filter?: ReceiptFilter): Promise<Receipt[]> => {
      await this.lat()
      this.guard()
      const behavior = getActiveBehavior()
      let items = Object.values(this.db.receipts)
      if (behavior?.receipts === 'empty') items = []
      if (filter?.instanceId) items = items.filter((r) => r.instanceId === filter.instanceId)
      if (filter?.result) items = items.filter((r) => r.result === filter.result)
      if (filter?.eventKind) items = items.filter((r) => r.eventKind === filter.eventKind)
      if (filter?.query) {
        const q = filter.query.toLowerCase()
        items = items.filter(
          (r) => r.actionName.toLowerCase().includes(q) || r.summary.toLowerCase().includes(q) || r.id.includes(q),
        )
      }
      items = items.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      if (filter?.limit) items = items.slice(0, filter.limit)
      return items
    },
    get: async (receiptId, expectedInstanceId) => {
      await this.lat()
      this.guard()
      const receipt = this.db.receipts[receiptId]
      if (!receipt) throw new ClientError('http', `Receipt not found: ${receiptId}`, { status: 404 })
      if (
        expectedInstanceId !== undefined &&
        receipt.instanceId !== expectedInstanceId
      ) {
        throw new ClientError(
          'validation',
          'The receipt belongs to a different application instance',
          { detail: `expected ${expectedInstanceId}, got ${receipt.instanceId}` },
        )
      }
      return receipt
    },
    verify: async (receiptId) => {
      await this.lat()
      this.guard()
      const receipt = this.db.receipts[receiptId]
      if (!receipt) throw new ClientError('http', `Receipt not found: ${receiptId}`, { status: 404 })
      const expected = fakeDigest(`${receipt.id}:${receipt.eventKind}`)
      const ok = receipt.payloadDigest?.value === expected.value
      return {
        ok,
        detail: ok
          ? 'Payload digest matches the recorded event.'
          : 'Payload digest mismatch — this receipt may have been modified.',
      }
    },
    exportJson: async (instanceId) => {
      await this.lat()
      this.guard()
      const items = Object.values(this.db.receipts).filter((r) => r.instanceId === instanceId)
      return JSON.stringify(items, null, 2)
    },
  }

  // ── conversation ─────────────────────────────────────────────────────────────

  conversation: StatePortClient['conversation'] = {
    get: async (instanceId): Promise<Conversation> => {
      const behavior = getActiveBehavior()
      await this.lat(behavior?.conversation === 'loading' ? 'conversation_load' : undefined)
      this.guard()
      const inst = this.requireInstance(instanceId)
      const conv = this.requireConversation(inst)
      const view: Conversation = JSON.parse(JSON.stringify(conv)) as Conversation
      if (behavior?.conversation === 'empty') view.messages = []
      if (behavior?.conversation === 'failed') {
        const lastAssistant = [...view.messages].reverse().find((m) => m.role === 'assistant')
        if (lastAssistant) {
          lastAssistant.state = 'failed'
        } else {
          view.messages.push({
            id: 'msg_scn_failed',
            conversationId: view.id,
            role: 'assistant',
            content: '',
            createdAt: nowIso(),
            state: 'failed',
            attachments: [],
            contextChips: [],
            toolEvents: [],
          })
        }
      }
      if (behavior?.conversation === 'streaming') {
        // Seed one in-flight assistant message; once it has been materialized
        // by a resume (and landed), it is not fabricated again.
        if (!view.messages.some((m) => m.id === STREAMING_SCENARIO_MESSAGE_ID)) {
          view.messages.push(scenarioStreamingMessage(view.id, this.nowMs()))
        }
      }
      return schemas.conversation.parse(view)
    },

    sendMessage: async (instanceId, input) => {
      await this.lat()
      this.guard()
      if (input.resumeMessageId) {
        throw new ClientError('validation', 'sendMessage always records a new message — resume a stream via streamMessage', {
          detail: 'Pass resumeMessageId to streamMessage to re-attach to an in-flight assistant reply.',
        })
      }
      const inst = this.requireInstance(instanceId)
      const conv = this.requireConversation(inst)
      const messageAt = () => (this.isStudyStateCapture(instanceId) ? this.clockIso() : nowIso())
      // Idempotent sends: a retry with the same clientMessageId returns the
      // already-recorded user message instead of duplicating it (contract §14).
      if (input.clientMessageId) {
        const existing = conv.messages.find((m) => m.id === input.clientMessageId && m.role === 'user')
        if (existing) {
          const idx = conv.messages.indexOf(existing)
          const followup = conv.messages.slice(idx + 1).find((m) => m.role === 'assistant')
          if (followup) {
            const reply = followup.content
            followup.content = ''
            followup.state = 'streaming'
            return { userMessage: existing, stream: this.createStream(conv, followup, reply) }
          }
          const assistantMessage: ConversationMessage = {
            id: this.nextConversationMessageId(instanceId, 'assistant'),
            conversationId: conv.id,
            role: 'assistant',
            content: '',
            createdAt: messageAt(),
            state: 'streaming',
            attachments: [],
            contextChips: [],
            toolEvents: [],
          }
          conv.messages.push(assistantMessage)
          conv.updatedAt = messageAt()
          this.persist()
          const reply = this.mockReply(inst, existing.content, existing.contextChips)
          return { userMessage: existing, stream: this.createStream(conv, assistantMessage, reply) }
        }
      }
      const userMessage: ConversationMessage = {
        id: input.clientMessageId ?? this.nextConversationMessageId(instanceId, 'user'),
        conversationId: conv.id,
        role: 'user',
        content: input.content,
        createdAt: messageAt(),
        state: 'complete',
        attachments: input.attachments ?? [],
        contextChips: input.contextChips ?? [],
        toolEvents: [],
      }
      const assistantMessage: ConversationMessage = {
        id: this.nextConversationMessageId(instanceId, 'assistant'),
        conversationId: conv.id,
        role: 'assistant',
        content: '',
        createdAt: messageAt(),
        state: 'streaming',
        attachments: [],
        contextChips: [],
        toolEvents: [],
      }
      conv.messages.push(userMessage, assistantMessage)
      conv.updatedAt = messageAt()
      this.persist()
      const reply = this.mockReply(inst, input.content, input.contextChips ?? [])
      const stream = this.createStream(conv, assistantMessage, reply)
      return { userMessage, stream }
    },

    streamMessage: async (instanceId, input) => {
      // Canonical streaming contract — identical semantics to sendMessage(),
      // plus re-attaching to an in-flight assistant reply on resumeMessageId.
      if (input.resumeMessageId) {
        await this.lat()
        this.guard()
        const inst = this.requireInstance(instanceId)
        const conv = this.requireConversation(inst)
        return this.resumeStream(inst, conv, input.resumeMessageId)
      }
      return this.conversation.sendMessage(instanceId, input)
    },

    retryLast: async (instanceId) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      const conv = this.requireConversation(inst)
      const lastAssistant = [...conv.messages].reverse().find((m) => m.role === 'assistant')
      if (!lastAssistant || (lastAssistant.state !== 'failed' && lastAssistant.state !== 'stopped')) {
        throw new ClientError('http', 'Nothing to retry', { status: 409 })
      }
      const lastUser = [...conv.messages].reverse().find((m) => m.role === 'user')
      lastAssistant.content = ''
      lastAssistant.state = 'streaming'
      this.persist()
      const reply = this.mockReply(inst, lastUser?.content ?? '', lastUser?.contextChips ?? [])
      return this.createStream(conv, lastAssistant, reply)
    },

    uploadAttachment: async (instanceId, input): Promise<Attachment> => {
      this.guard()
      // The mock enforces the same authoritative policy as the service so a
      // Scenario Lab demo can never accept what production would reject.
      const policy = checkAttachment(input.name, input.mimeType, input.sizeBytes)
      if (!policy.ok) throw new ClientError('validation', policy.reason)
      const behavior = getActiveBehavior()
      // Simulated progress: two short hops, then success or scenario failure.
      await this.lat()
      await this.lat()
      const failed = behavior?.attachmentUploadFails === true
      const attachment: Attachment = {
        id: nextId(this.db, 'att'),
        name: input.name,
        mimeType: input.mimeType,
        sizeBytes: input.sizeBytes,
        state: failed ? 'failed' : 'ready',
        progress: failed ? 64 : 100,
        error: failed ? 'Upload failed before completion. Nothing was stored — retry is safe.' : undefined,
        retentionNote: 'Attachments stay on this machine with the conversation.',
      }
      void instanceId
      return attachment
    },

    deleteAttachment: async (instanceId, attachmentId) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      const conv = inst.conversationId
        ? this.db.conversations[inst.conversationId]
        : undefined
      if (!conv) return
      for (const msg of conv.messages) {
        msg.attachments = msg.attachments.filter((a) => a.id !== attachmentId)
      }
      this.persist()
    },

    exportConversation: async (instanceId) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      const conv = this.requireConversation(inst)
      const lines = [
        `# Conversation — ${inst.name}`,
        '',
        `Exported ${new Date(this.nowMs()).toLocaleString()}.`,
        '',
      ]
      for (const msg of conv.messages) {
        const who = msg.role === 'user' ? 'You' : msg.role === 'assistant' ? 'Assistant' : 'System'
        lines.push(`## ${who} — ${new Date(msg.createdAt).toLocaleString()}`, '', msg.content, '')
      }
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'Conversation exported',
        eventKind: 'conversation.export',
        summary: `Conversation exported as Markdown (${conv.messages.length} messages).`,
        relatedConversationId: conv.id,
      })
      this.persist()
      return { markdown: lines.join('\n'), receipt }
    },

    clearConversation: async (instanceId) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      const conv = this.requireConversation(inst)
      const removed = conv.messages.length
      conv.messages = []
      conv.updatedAt = this.isStudyStateCapture(inst.id) ? this.clockIso() : nowIso()
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'Conversation cleared',
        eventKind: 'conversation.clear',
        result: 'completed_without_change',
        summary: `The operational conversation transcript was cleared (${removed} messages removed) without changing canonical application state.`,
        relatedConversationId: conv.id,
      })
      receipt.validation = {
        state: 'not_required',
        detail: 'This receipt records an operational transcript lifecycle action; canonical application state is explicitly unchanged.',
      }
      this.persist()
      return { receipt }
    },
  }

  /**
   * Re-attach to an in-flight assistant reply (streamMessage with
   * resumeMessageId). The scenario-seeded live message is materialized into
   * the conversation on first attach so progress, stop and retry survive a
   * reload; any other streaming-state message continues from its persisted
   * partial content. A message with no live stream rejects honestly so the
   * surface can mark it interrupted and offer retry.
   */
  private resumeStream(
    inst: ApplicationInstance,
    conv: Conversation,
    messageId: string,
  ): { userMessage: ConversationMessage | null; stream: MessageStream } {
    const behavior = getActiveBehavior()
    let message = conv.messages.find((m) => m.id === messageId && m.role === 'assistant')
    if (!message && behavior?.conversation === 'streaming' && messageId === STREAMING_SCENARIO_MESSAGE_ID) {
      message = scenarioStreamingMessage(conv.id, this.nowMs())
      conv.messages.push(message)
      conv.updatedAt = this.isStudyStateCapture(inst.id) ? this.clockIso() : nowIso()
      this.persist()
    }
    if (!message || message.state !== 'streaming') {
      throw new ClientError('unavailable', 'There is no live stream for that message to resume', {
        detail: `Message ${messageId} is not in a streaming state.`,
      })
    }
    const messageIndex = conv.messages.indexOf(message)
    const lastUser = [...conv.messages.slice(0, messageIndex)].reverse().find((m) => m.role === 'user') ?? null
    // The full reply is deterministic: the scenario text for the seeded live
    // message, otherwise the same generator that produced the partial content.
    const full =
      message.id === STREAMING_SCENARIO_MESSAGE_ID && behavior?.conversation === 'streaming'
        ? STREAMING_SCENARIO_FULL_TEXT
        : this.mockReply(inst, lastUser?.content ?? '', lastUser?.contextChips ?? [])
    let remainder = full
    if (message.content) {
      if (full.startsWith(message.content)) {
        remainder = full.slice(message.content.length)
      } else {
        // The reply cannot be reproduced exactly (behavior changed since the
        // partial content was written): regenerate coherently from scratch.
        message.content = ''
      }
    }
    return { userMessage: lastUser, stream: this.createStream(conv, message, remainder) }
  }

  private mockReply(inst: ApplicationInstance, content: string, chips: ContextChip[]): string {
    const behavior = getActiveBehavior()
    if (behavior?.conversation === 'failed') {
      return '__fail__'
    }
    const lower = content.toLowerCase()
    const chipNote =
      chips.length > 0
        ? ` Using the context you attached (${chips.map((c) => c.label).join(', ')}).`
        : ''
    if (inst.id === INSTANCE_IDS.nixosInfra) {
      if (lower.includes('plan') || lower.includes('start') || lower.includes('vm')) {
        return `The prepared plan starts \`homelab-dev\` in three steps: verify the target identity, power on the VM, then wait for SSH. Nothing on disk changes, and stopping later is a one-click rollback.${chipNote}\n\nBecause no daily-driver authorization covers this target yet, the plan needs your approval before it can run. The exact scope is in the approvals inbox.`
      }
      return `Repository \`nixos-homelab\` is clean at \`main\`, the VM is stopped, and health has not been checked. The useful next step is starting the VM — I prepared that plan and it is waiting for approval.${chipNote}\n\nAfter it runs, I would validate the flake and run the health check so the target shows a verified state again.`
    }
    if (inst.id === INSTANCE_IDS.studyAlpha) {
      return `You are 62% toward “Pass the NixOS fundamentals assessment”. The open thread is the module system: finish the reading, then do the parametrize exercise — that pairing carries the most assessment weight.${chipNote}\n\nYour evidence note on the module mental model is still a draft; tightening it after the exercise should take one focused session.`
    }
    if (inst.id === INSTANCE_IDS.checklistSample) {
      return `Three of five items are open. The natural next one is “Open the receipt for the change” — it shows how this sample records state changes.${chipNote}`
    }
    if (lower.includes('backup')) {
      return `The last backup of this application is 31 hours old against a 24-hour interval, so backup is due. You can run one from the overview — it is a local operation and produces a receipt.${chipNote}\n\nNothing else is blocked: the repository is clean and there are no pending approvals for this instance.`
    }
    return `Here is where things stand: conversation, files, terminal and receipts are available, the project repository is clean, and the only housekeeping item is the overdue backup.${chipNote}\n\nIf you want, I can draft the exact steps for the next task — anything I propose still goes through the normal review before it changes state.`
  }

  private createStream(conv: Conversation, message: ConversationMessage, reply: string): MessageStream {
    const behavior = getActiveBehavior()
    const fail = reply === '__fail__' || behavior?.conversation === 'failed'
    const words = reply.split(/(?<=\s)/)
    let stopped = false
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- generator functions cannot be arrow-bound; the alias is the capture.
    const self = this
    const iterator = async function* (): AsyncGenerator<ConversationStreamChunk> {
      const perChunk = behavior?.conversation === 'streaming' ? 1 : 3
      for (let i = 0; i < words.length; i += perChunk) {
        if (stopped) {
          message.state = 'stopped'
          self.persist()
          yield { type: 'stopped', message: { ...message } }
          return
        }
        if (fail && i >= 6) {
          message.state = 'failed'
          self.persist()
          yield { type: 'error', message: 'The response failed before completion. Your message is preserved — retry is safe.' }
          return
        }
        await sleep(behavior?.conversation === 'streaming' ? 220 : 30)
        const text = words.slice(i, i + perChunk).join('')
        message.content += text
        yield { type: 'delta', text }
      }
      message.state = 'complete'
      const instance = self.db.instances.find((candidate) => candidate.conversationId === conv.id)
      conv.updatedAt = instance && self.isStudyStateCapture(instance.id) ? self.clockIso() : nowIso()
      self.persist()
      yield { type: 'done', message: { ...message } }
    }
    return {
      messageId: message.id,
      [Symbol.asyncIterator]() {
        return iterator()
      },
      stop() {
        stopped = true
      },
    }
  }

  // ── files ────────────────────────────────────────────────────────────────────

  files: StatePortClient['files'] = {
    listTree: async (instanceId): Promise<FileNode[]> => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const behavior = getActiveBehavior()
      if (behavior?.files === 'empty') return []
      const records = this.db.files[instanceId] ?? {}
      const tree = buildFileTree(instanceId, records)
      this.fileTreeBases.add(instanceId)
      if (behavior?.files === 'read_only') {
        const mark = (nodes: FileNode[]) =>
          nodes.forEach((n) => {
            if (n.kind === 'file') n.readOnly = true
            if (n.children) mark(n.children)
          })
        mark(tree)
      }
      if (behavior?.files === 'dirty') {
        const first = tree.flatMap(function flatten(n): FileNode[] {
          return n.kind === 'file' ? [n] : (n.children ?? []).flatMap(flatten)
        })[0]
        if (first) first.gitStatus = 'modified'
      }
      return tree
    },

    read: async (instanceId, path): Promise<FileEntry> => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      this.assertPathAllowed(path)
      const rec = this.db.files[instanceId]?.[path]
      if (!rec) throw new ClientError('http', `File not found: ${path}`, { status: 404 })
      const behavior = getActiveBehavior()
      this.fileReadRevisions.set(`${instanceId}\u001f${path}`, rec.revision)
      return {
        path,
        content: rec.content,
        revision: rec.revision,
        readOnly: rec.readOnly || behavior?.files === 'read_only',
        encoding: 'utf-8',
        modifiedAt: rec.modifiedAt,
      }
    },

    write: async (instanceId, path, input): Promise<WriteFileResult> => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const behavior = getActiveBehavior()
      if (path.includes('..') || path.startsWith('/') || path.startsWith('~')) {
        return {
          ok: false,
          reason: 'path_policy',
          detail: `“${path}” is outside the permitted project root for this application.`,
        }
      }
      const rec: MockFileRecord | undefined = this.db.files[instanceId]?.[path]
      if (!rec) {
        return { ok: false, reason: 'validation', detail: `“${path}” does not exist in this project.` }
      }
      if (rec.readOnly || behavior?.files === 'read_only') {
        return { ok: false, reason: 'read_only', detail: `“${path}” is read-only.` }
      }
      if (behavior?.files === 'write_failed') {
        return {
          ok: false,
          reason: 'validation',
          detail: 'The write was rejected by the simulated service. Your editor content is preserved.',
        }
      }
      if (input.expectedRevision !== rec.revision) {
        return {
          ok: false,
          reason: 'conflict',
          detail: `“${path}” changed since you opened it. Reload to see the current version before overwriting.`,
          currentRevision: rec.revision,
          currentContent: rec.content,
        }
      }
      const diff = unifiedDiff(path, rec.content, input.content)
      const beforeRevision = rec.revision
      rec.content = input.content
      rec.revision = `rev_${fakeHex(input.content, 12)}`
      rec.modifiedAt = nowIso()
      const change = {
        id: nextId(this.db, 'fc'),
        instanceId,
        path,
        beforeRevision,
        afterRevision: rec.revision,
        diff,
        createdAt: nowIso(),
      }
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'File change saved',
        eventKind: 'file.write',
        summary: `${path} updated (${diff.addedLines} added, ${diff.removedLines} removed).`,
        diff,
        expectedRevision: beforeRevision,
        resultRevision: rec.revision,
      })
      this.persist()
      return {
        ok: true,
        change,
        receipt,
        entry: {
          path,
          content: rec.content,
          revision: rec.revision,
          readOnly: rec.readOnly,
          encoding: 'utf-8',
          modifiedAt: rec.modifiedAt,
        },
      }
    },

    create: async (instanceId, path, input) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const behavior = getActiveBehavior()
      if (!this.fileTreeBases.has(instanceId)) {
        throw new ClientError('validation', 'The project tree must be listed before a file can be created')
      }
      if (path.includes('..') || path.startsWith('/') || path.startsWith('~')) {
        return { ok: false, reason: 'path_policy', detail: `“${path}” is outside the permitted project root.` }
      }
      if (!path || path.endsWith('/')) {
        return { ok: false, reason: 'validation', detail: 'Enter a regular file path, not a directory.' }
      }
      if (behavior?.files === 'read_only') {
        return { ok: false, reason: 'read_only', detail: 'This application file workspace is read-only.' }
      }
      if (behavior?.files === 'write_failed') {
        return { ok: false, reason: 'validation', detail: 'The create was rejected by the simulated service.' }
      }
      const records = (this.db.files[instanceId] ??= {})
      if (records[path]) {
        return { ok: false, reason: 'conflict', detail: `“${path}” already exists.` }
      }
      const modifiedAt = nowIso()
      const revision = `rev_${fakeHex(input.content, 12)}`
      records[path] = { content: input.content, revision, readOnly: false, modifiedAt }
      this.fileReadRevisions.set(`${instanceId}\u001f${path}`, revision)
      const diff = unifiedDiff(path, '', input.content)
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'File created',
        eventKind: 'file.create',
        summary: `${path} created (${diff.addedLines} added).`,
        diff,
        resultRevision: revision,
      })
      this.persist()
      return {
        ok: true,
        path,
        diff,
        receipt,
        entry: {
          path,
          content: input.content,
          revision,
          readOnly: false,
          encoding: 'utf-8' as const,
          modifiedAt,
        },
      }
    },

    rename: async (instanceId, sourcePath, input) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const behavior = getActiveBehavior()
      if (
        sourcePath.includes('..') ||
        sourcePath.startsWith('/') ||
        sourcePath.startsWith('~') ||
        input.destinationPath.includes('..') ||
        input.destinationPath.startsWith('/') ||
        input.destinationPath.startsWith('~')
      ) {
        return { ok: false, reason: 'path_policy', detail: 'The rename target is outside the permitted project root.' }
      }
      const records = this.db.files[instanceId] ?? {}
      const record = records[sourcePath]
      if (!record) return { ok: false, reason: 'conflict', detail: `“${sourcePath}” no longer exists.` }
      const observed = this.fileReadRevisions.get(`${instanceId}\u001f${sourcePath}`)
      if (!observed) {
        throw new ClientError('validation', 'The file must be read before its path can be changed')
      }
      if (record.readOnly || behavior?.files === 'read_only') {
        return { ok: false, reason: 'read_only', detail: `“${sourcePath}” is read-only.` }
      }
      if (behavior?.files === 'write_failed') {
        return { ok: false, reason: 'validation', detail: 'The rename was rejected by the simulated service.' }
      }
      if (observed !== input.expectedRevision || record.revision !== input.expectedRevision) {
        return { ok: false, reason: 'conflict', detail: `“${sourcePath}” changed since it was reviewed.` }
      }
      if (!input.destinationPath || input.destinationPath.endsWith('/')) {
        return { ok: false, reason: 'validation', detail: 'Enter a regular file destination.' }
      }
      if (records[input.destinationPath]) {
        return { ok: false, reason: 'conflict', detail: `“${input.destinationPath}” already exists.` }
      }
      delete records[sourcePath]
      records[input.destinationPath] = record
      this.fileReadRevisions.delete(`${instanceId}\u001f${sourcePath}`)
      this.fileReadRevisions.set(`${instanceId}\u001f${input.destinationPath}`, record.revision)
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'File renamed',
        eventKind: 'file.rename',
        summary: `${sourcePath} renamed to ${input.destinationPath}.`,
        expectedRevision: record.revision,
        resultRevision: record.revision,
      })
      this.persist()
      return {
        ok: true,
        sourcePath,
        destinationPath: input.destinationPath,
        receipt,
        entry: {
          path: input.destinationPath,
          content: record.content,
          revision: record.revision,
          readOnly: record.readOnly,
          encoding: 'utf-8' as const,
          modifiedAt: record.modifiedAt,
        },
      }
    },

    delete: async (instanceId, path, input) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const behavior = getActiveBehavior()
      if (path.includes('..') || path.startsWith('/') || path.startsWith('~')) {
        return { ok: false, reason: 'path_policy', detail: `“${path}” is outside the permitted project root.` }
      }
      const records = this.db.files[instanceId] ?? {}
      const record = records[path]
      if (!record) return { ok: false, reason: 'conflict', detail: `“${path}” no longer exists.` }
      const observed = this.fileReadRevisions.get(`${instanceId}\u001f${path}`)
      if (!observed) {
        throw new ClientError('validation', 'The file must be read before its path can be changed')
      }
      if (record.readOnly || behavior?.files === 'read_only') {
        return { ok: false, reason: 'read_only', detail: `“${path}” is read-only.` }
      }
      if (behavior?.files === 'write_failed') {
        return { ok: false, reason: 'validation', detail: 'The delete was rejected by the simulated service.' }
      }
      if (observed !== input.expectedRevision || record.revision !== input.expectedRevision) {
        return { ok: false, reason: 'conflict', detail: `“${path}” changed since it was reviewed.` }
      }
      delete records[path]
      this.fileReadRevisions.delete(`${instanceId}\u001f${path}`)
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'File deleted',
        eventKind: 'file.delete',
        summary: `${path} deleted.`,
        expectedRevision: record.revision,
      })
      this.persist()
      return { ok: true, path, receipt }
    },
  }

  private assertPathAllowed(path: string): void {
    if (path.includes('..') || path.startsWith('/') || path.startsWith('~')) {
      throw new ClientError('http', 'Path is outside the permitted project root', { status: 403 })
    }
  }

  // ── terminal ─────────────────────────────────────────────────────────────────

  terminal: StatePortClient['terminal'] = {
    inputMode: 'line_commands',

    listTargets: async (instanceId): Promise<TerminalTarget[]> => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const behavior = getActiveBehavior()
      if (instanceId === INSTANCE_IDS.ctoPilot) {
        return [
          { id: TARGET_IDS.ctoPty, instanceId, label: 'Local PTY for StatePort CTO Pilot', kind: 'local_pty', available: true },
        ]
      }
      if (instanceId === INSTANCE_IDS.nixosInfra) {
        const target = this.viewInfraTarget(instanceId)
        const vmRunning = target.vm.state === 'running'
        return [
          { id: TARGET_IDS.nixosPty, instanceId, label: 'Local PTY for NixOS Infrastructure', kind: 'local_pty', available: true },
          {
            id: `${TARGET_IDS.nixosVm}_ssh`,
            instanceId,
            label: 'SSH to homelab-dev',
            kind: 'ssh',
            available: vmRunning && !behavior?.targetUnavailable,
            unavailableReason: vmRunning ? undefined : 'SSH is unavailable while the virtual machine is stopped.',
          },
        ]
      }
      return []
    },

    listSessions: async (instanceId): Promise<TerminalSession[]> => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      return [...this.terminalSessions.values()].filter((s) => s.instanceId === instanceId)
    },

    createSession: async (instanceId, targetId, name) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const session: TerminalSession = {
        id: nextId(this.db, 'term'),
        targetId,
        instanceId,
        name: name ?? `Terminal ${this.terminalSessions.size + 1}`,
        state: 'idle',
        cwd: this.cwdFor(instanceId),
        createdAt: nowIso(),
      }
      this.terminalSessions.set(session.id, session)
      this.persist()
      return session
    },

    renameSession: async (sessionId, name) => {
      await this.lat()
      this.guard()
      const session = this.requireSession(sessionId)
      session.name = name
      return session
    },

    connect: async (sessionId) => {
      const behavior = getActiveBehavior()
      await this.lat(behavior?.terminal === 'connecting' ? 'conversation_load' : undefined)
      this.guard()
      const session = this.requireSession(sessionId)
      if (session.state === 'ended') {
        throw new ClientError('http', 'Session has ended — create a new session', { status: 409 })
      }
      if (behavior?.terminal === 'failed') {
        session.state = 'failed'
        session.lastError = 'Connection failed. The target did not answer; your session state is preserved for reconnect.'
        this.emit(session.id, { type: 'state', state: 'failed', error: session.lastError })
        return session
      }
      session.state = 'connected'
      session.lastError = undefined
      this.emit(session.id, { type: 'state', state: 'connected' })
      this.emit(session.id, {
        type: 'output',
        text: `\x1b[2mConnected to ${session.targetId === `${TARGET_IDS.nixosVm}_ssh` ? 'homelab-dev (ssh)' : 'local shell'} · ${session.cwd}\x1b[0m\r\n`,
      })
      return session
    },

    disconnect: async (sessionId) => {
      await this.lat()
      this.guard()
      const session = this.requireSession(sessionId)
      session.state = 'idle'
      this.emit(session.id, { type: 'state', state: 'idle' })
      return session
    },

    reconnect: async (sessionId) => {
      const behavior = getActiveBehavior()
      await this.lat(behavior?.terminal === 'reconnecting' ? 'conversation_load' : undefined)
      this.guard()
      const session = this.requireSession(sessionId)
      if (session.state === 'ended') {
        throw new ClientError('http', 'Session has ended — create a new session', { status: 409 })
      }
      session.state = 'reconnecting'
      this.emit(session.id, { type: 'state', state: 'reconnecting' })
      await sleep(200)
      if (behavior?.terminal === 'failed') {
        session.state = 'failed'
        session.lastError = 'Reconnect failed. The target is still unreachable.'
        this.emit(session.id, { type: 'state', state: 'failed', error: session.lastError })
        return session
      }
      session.state = 'connected'
      session.lastError = undefined
      this.emit(session.id, { type: 'state', state: 'connected' })
      this.emit(session.id, { type: 'output', text: '\x1b[2mReconnected · scrollback preserved\x1b[0m\r\n' })
      return session
    },

    endSession: async (sessionId) => {
      await this.lat()
      this.guard()
      const session = this.requireSession(sessionId)
      session.state = 'ended'
      this.emit(session.id, { type: 'state', state: 'ended' })
      this.emit(session.id, { type: 'exit', code: 0 })
      return session
    },

    runCommand: async (sessionId, command): Promise<CommandResult> => {
      await this.lat()
      this.guard()
      const session = this.requireSession(sessionId)
      if (session.state !== 'connected') {
        throw new ClientError('http', 'Terminal is not connected', { status: 409 })
      }
      const result = this.interpret(session, command.trim())
      const text = result.output ? `${result.output.replaceAll('\n', '\r\n')}\r\n` : ''
      if (result.clear) {
        this.emit(session.id, { type: 'output', text: '\x1b[2J\x1b[H' })
      } else if (text) {
        this.emit(session.id, { type: 'output', text })
      }
      if (result.exit) {
        session.state = 'ended'
        this.emit(session.id, { type: 'state', state: 'ended' })
        this.emit(session.id, { type: 'exit', code: 0 })
      }
      return { output: result.output, exitCode: result.exitCode }
    },

    sendInput: (sessionId, data) => {
      // Raw-input channel (mirrors the HTTP raw PTY): bytes accumulate until
      // CR, then the mock line discipline interprets the line.
      const session = this.requireSession(sessionId)
      if (session.state !== 'connected') {
        throw new ClientError('http', 'Terminal is not connected', { status: 409 })
      }
      const buffer = (this.terminalInputBuffers.get(sessionId) ?? '') + data
      const lines = buffer.split('\r')
      this.terminalInputBuffers.set(sessionId, lines.pop() ?? '')
      for (const rawLine of lines) {
        const line = rawLine.replace(/\n/g, '')
        const result = this.interpret(session, line.trim())
        const echo = `${line}\r\n`
        if (result.clear) {
          this.emit(session.id, { type: 'output', text: echo + '\x1b[2J\x1b[H' })
        } else {
          const text = result.output ? `${result.output.replaceAll('\n', '\r\n')}\r\n` : ''
          this.emit(session.id, { type: 'output', text: echo + text })
        }
        if (result.exit) {
          session.state = 'ended'
          this.emit(session.id, { type: 'state', state: 'ended' })
          this.emit(session.id, { type: 'exit', code: 0 })
        }
      }
    },

    resize: () => {
      // Mock no-op: there is no kernel to notify about viewport resizes.
    },

    subscribe: (sessionId, listener) => {
      let set = this.terminalListeners.get(sessionId)
      if (!set) {
        set = new Set()
        this.terminalListeners.set(sessionId, set)
      }
      set.add(listener)
      return () => {
        set.delete(listener)
      }
    },
  }

  private emit(sessionId: string, event: TerminalSessionEvent): void {
    this.terminalListeners.get(sessionId)?.forEach((l) => l(event))
  }

  private requireSession(sessionId: string): TerminalSession {
    const session = this.terminalSessions.get(sessionId)
    if (!session) throw new ClientError('http', `Terminal session not found: ${sessionId}`, { status: 404 })
    return session
  }

  private cwdFor(instanceId: string): string {
    if (instanceId === INSTANCE_IDS.nixosInfra) return '~/nixos-homelab'
    if (instanceId === INSTANCE_IDS.ctoPilot) return '~/cto-pilot'
    return '~'
  }

  private interpret(
    session: TerminalSession,
    command: string,
  ): { output: string; exitCode: number; clear?: boolean; exit?: boolean } {
    const inst = this.db.instances.find((i) => i.id === session.instanceId)
    const files = this.db.files[session.instanceId] ?? {}
    const topLevel = [
      ...new Set(
        Object.keys(files).map((p) => {
          const first = p.split('/')[0]
          return p.includes('/') ? `${first}/` : first
        }),
      ),
    ].sort()
    const repo = inst?.repository
    const dirty = getActiveBehavior()?.repoDirty === true || repo?.clean === false
    switch (command) {
      case '':
        return { output: '', exitCode: 0 }
      case 'help':
        return {
          output: [
            'Available commands in this mock shell:',
            '  help                    show this help',
            '  pwd                     print working directory',
            '  ls                      list project files',
            '  cat README.md           print the README',
            '  git status              repository state',
            '  git log --oneline -5    recent commits',
            '  nix flake check         validate the flake',
            '  clear                   clear the screen',
            '  exit                    end the session',
          ].join('\n'),
          exitCode: 0,
        }
      case 'pwd':
        return { output: session.cwd.replace('~', '/workspace/kim'), exitCode: 0 }
      case 'ls':
        return { output: topLevel.length ? topLevel.join('  ') : '', exitCode: 0 }
      case 'cat README.md': {
        const readme = files['README.md']
        if (!readme) return { output: 'cat: README.md: No such file or directory', exitCode: 1 }
        return { output: readme.content.replace(/\n$/, ''), exitCode: 0 }
      }
      case 'git status': {
        if (!repo) return { output: 'fatal: not a git repository', exitCode: 128 }
        if (dirty) {
          return {
            output: [
              `On branch ${repo.branch}`,
              'Changes not staged for commit:',
              '  modified:   hosts/homelab/configuration.nix',
              '',
              'no changes added to commit',
            ].join('\n'),
            exitCode: 0,
          }
        }
        return {
          output: [`On branch ${repo.branch}`, `Your branch is up to date with 'origin/${repo.branch}'.`, '', 'nothing to commit, working tree clean'].join('\n'),
          exitCode: 0,
        }
      }
      case 'git log --oneline -5': {
        if (!repo) return { output: 'fatal: not a git repository', exitCode: 128 }
        const commits =
          session.instanceId === INSTANCE_IDS.nixosInfra
            ? [
                ['a1b2c3d4e5', 'homelab: set timezone to Europe/Berlin'],
                ['f6e5d4c3b2', 'modules: extract shared services.nix'],
                ['9a8b7c6d5e', 'flake: pin nixpkgs 24.05'],
                ['1a2b3c4d5e', 'hosts: add qemu guest profile'],
                ['5e4d3c2b1a', 'Initial homelab configuration'],
              ]
            : [
                ['c7d8e9f0a1', 'notes: pilot week 2 summary'],
                ['b2c3d4e5f6', 'chore: bump pilot version'],
                ['a9b8c7d6e5', 'Add pilot notes'],
                ['98a7b6c5d4', 'Initial pilot scaffold'],
                ['1122334455', 'Import repository'],
              ]
        return { output: commits.map(([h, m]) => `${h} ${m}`).join('\n'), exitCode: 0 }
      }
      case 'nix flake check': {
        if (session.instanceId !== INSTANCE_IDS.nixosInfra) {
          return { output: 'error: could not find a flake.nix in the current directory', exitCode: 1 }
        }
        return {
          output: [
            'evaluating flake...',
            'checking flake output ‘nixosConfigurations’...',
            'checking NixOS configuration ‘nixosConfigurations.homelab’...',
            'ok — 1 configuration evaluated, 0 errors, 0 warnings',
          ].join('\n'),
          exitCode: 0,
        }
      }
      case 'clear':
        return { output: '', exitCode: 0, clear: true }
      case 'exit':
        return { output: 'logout', exitCode: 0, exit: true }
      default:
        return { output: `${command.split(' ')[0]}: command not found — try 'help'`, exitCode: 127 }
    }
  }

  // ── infrastructure ───────────────────────────────────────────────────────────

  private viewInfraTarget(instanceId: string): InfrastructureTarget {
    const base = this.db.infraTargets[instanceId]
    if (!base) {
      throw new ClientError('unavailable', 'No infrastructure target is registered for this application', {
        detail: 'Infrastructure truth cannot be verified without a target.',
      })
    }
    const target: InfrastructureTarget = JSON.parse(JSON.stringify(base)) as InfrastructureTarget
    const behavior = getActiveBehavior()
    if (behavior?.targetUnavailable) {
      target.available = false
      target.unavailableReason = 'The target cannot be verified. The local VM runtime did not answer.'
      target.vm = { state: 'unavailable' }
      target.ssh = { state: 'not_checked' }
      target.health = { state: 'unavailable' }
      return target
    }
    if (behavior?.repoDirty) target.repository = { ...target.repository, clean: false }
    if (behavior?.vm === 'running_unchecked') {
      target.vm = { state: 'running', since: new Date(Date.now() - 25 * 60_000).toISOString() }
      target.ssh = { state: 'ready' }
      target.health = { state: 'not_checked' }
    }
    if (behavior?.vm === 'healthy') {
      target.vm = { state: 'running', since: new Date(Date.now() - 2 * 3_600_000).toISOString() }
      target.ssh = { state: 'ready' }
      target.health = { state: 'healthy', checkedAt: new Date(Date.now() - 10 * 60_000).toISOString(), detail: 'All checks passed.' }
    }
    return target
  }

  private planStepsFor(operation: InfrastructureOperation): InfrastructurePlan['steps'] {
    switch (operation) {
      case 'observe':
        return [
          { id: 'ps_1', title: 'Read target state', detail: 'stateport vm observe homelab-dev', kind: 'check' },
          { id: 'ps_2', title: 'Probe SSH readiness', detail: 'stateport ssh probe --timeout 5s', kind: 'check' },
        ]
      case 'validate':
        return [
          { id: 'ps_1', title: 'Evaluate the flake', detail: 'nix flake check', kind: 'command' },
          { id: 'ps_2', title: 'Compare against target revision', detail: 'stateport target diff-revision', kind: 'check' },
        ]
      case 'health_check':
        return [
          { id: 'ps_1', title: 'Run health checks', detail: 'stateport health run homelab-dev', kind: 'command' },
          { id: 'ps_2', title: 'Record result', detail: 'stateport health record', kind: 'check' },
        ]
      case 'create_or_update':
        return [
          { id: 'ps_1', title: 'Verify repository identity', detail: 'stateport target verify homelab-dev', kind: 'check' },
          { id: 'ps_2', title: 'Apply repository workflow', detail: 'make vm-persistent-create', kind: 'command' },
          { id: 'ps_3', title: 'Observe resulting target', detail: 'stateport vm observe homelab-dev', kind: 'check' },
        ]
      case 'start':
        return [
          { id: 'ps_1', title: 'Verify target identity', detail: 'stateport target verify homelab-dev', kind: 'check' },
          { id: 'ps_2', title: 'Start the virtual machine', detail: 'stateport vm start homelab-dev', kind: 'command' },
          { id: 'ps_3', title: 'Wait for SSH', detail: 'stateport ssh wait --timeout 120s', kind: 'command' },
          { id: 'ps_4', title: 'Confirm power state', detail: 'stateport vm observe homelab-dev', kind: 'check' },
        ]
      case 'stop':
        return [
          { id: 'ps_1', title: 'Verify target identity', detail: 'stateport target verify homelab-dev', kind: 'check' },
          { id: 'ps_2', title: 'Graceful shutdown', detail: 'stateport vm stop homelab-dev --graceful', kind: 'command' },
          { id: 'ps_3', title: 'Confirm power state', detail: 'stateport vm observe homelab-dev', kind: 'check' },
        ]
      case 'restart':
        return [
          { id: 'ps_1', title: 'Graceful shutdown', detail: 'stateport vm stop homelab-dev --graceful', kind: 'command' },
          { id: 'ps_2', title: 'Start the virtual machine', detail: 'stateport vm start homelab-dev', kind: 'command' },
          { id: 'ps_3', title: 'Wait for SSH', detail: 'stateport ssh wait --timeout 120s', kind: 'command' },
        ]
      case 'destroy':
        return [
          { id: 'ps_1', title: 'Verify target identity', detail: 'stateport target verify homelab-dev', kind: 'check' },
          { id: 'ps_2', title: 'Confirm exact target name', detail: 'interactive confirmation gate', kind: 'gate' },
          { id: 'ps_3', title: 'Destroy the virtual machine', detail: 'stateport vm destroy homelab-dev', kind: 'command' },
        ]
    }
  }

  infrastructure: StatePortClient['infrastructure'] = {
    canRevokeAuthorization: true,
    getTarget: async (instanceId): Promise<InfrastructureTarget> => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      return this.viewInfraTarget(instanceId)
    },

    observe: async (instanceId) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const target = this.viewInfraTarget(instanceId)
      this.addActivity({
        instanceId,
        kind: 'infrastructure.observe',
        title: 'Target observed',
        detail: `VM ${target.vm.state} · SSH ${target.ssh.state.replaceAll('_', ' ')} · health ${target.health.state.replaceAll('_', ' ')}`,
      })
      this.persist()
      return target
    },

    validateConfiguration: async (instanceId) => {
      await this.lat()
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'Configuration validated',
        eventKind: 'infrastructure.validate',
        summary: 'nix flake check passed for nixos-homelab @ main.',
      })
      this.persist()
      return { ok: true, detail: 'nix flake check passed — 1 configuration evaluated, 0 errors.', receipt }
    },

    healthCheck: async (instanceId) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const target = this.viewInfraTarget(instanceId)
      if (target.vm.state !== 'running') {
        throw new ClientError('http', 'Cannot run a health check while the virtual machine is stopped', {
          status: 409,
        })
      }
      const base = this.db.infraTargets[instanceId]
      base.health = { state: 'healthy', checkedAt: nowIso(), detail: 'All checks passed.' }
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'Health check passed',
        eventKind: 'infrastructure.health_check',
        summary: 'All health checks passed on homelab-dev.',
      })
      this.persist()
      return { target: this.viewInfraTarget(instanceId), receipt }
    },

    preparePlan: async (instanceId, operation): Promise<InfrastructurePlan> => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const target = this.viewInfraTarget(instanceId)
      if (!target.available) {
        throw new ClientError('unavailable', 'Cannot prepare a plan — the target is unavailable')
      }
      const extras = this.refreshExtras()
      const grant =
        this.db.authorizations[instanceId] ?? extras.authorizations[instanceId] ?? null
      const routineCovered =
        grant?.status === 'active' &&
        (!grant.expiresAt || new Date(grant.expiresAt).getTime() > Date.now()) &&
        grant.covers.includes(operation)
      const readOnly = operation === 'observe' || operation === 'validate' || operation === 'health_check'
      const requiresApproval = !readOnly && operation !== 'destroy' ? !routineCovered : operation === 'destroy'
      const id = nextId(this.db, 'plan')
      const titles: Record<InfrastructureOperation, string> = {
        observe: 'Observe target state',
        validate: 'Validate Nix configuration',
        health_check: 'Run health checks',
        create_or_update: 'Create or update virtual machine',
        start: 'Start virtual machine',
        stop: 'Stop virtual machine (graceful)',
        restart: 'Restart virtual machine',
        destroy: 'Destroy virtual machine',
      }
      const plan: InfrastructurePlan = {
        id,
        instanceId,
        targetId: target.id,
        operation,
        title: titles[operation],
        state: requiresApproval ? 'awaiting_approval' : 'prepared',
        risk: operation === 'destroy' ? 'high' : readOnly ? 'low' : 'medium',
        requiresApproval,
        coveredByAuthorization: routineCovered === true,
        steps: this.planStepsFor(operation),
        digest: fakeDigest(`plan:${id}:${operation}`),
        beforeSummary: beforeSummaryFor(target),
        afterSummary: afterSummaryFor(operation),
        rollbackNotes: rollbackFor(operation),
        createdAt: nowIso(),
      }
      this.db.plans[id] = plan
      if (requiresApproval) {
        const approvalId = nextId(this.db, 'appr')
        const approval: Approval = {
          id: approvalId,
          instanceId,
          kind: 'infrastructure_plan',
          title: titles[operation],
          operationType: `Infrastructure · ${operation.replace('_', ' ')}`,
          risk: plan.risk,
          status: 'pending',
          scope: [
            `Target: ${target.name} (local virtual machine)`,
            `Operation: ${operation.replace('_', ' ')}`,
            `Repository: ${target.repository.name} @ ${target.repository.branch} (${target.repository.clean ? 'clean' : 'uncommitted changes'})`,
          ],
          beforeSummary: plan.beforeSummary,
          afterSummary: plan.afterSummary,
          planDigest: plan.digest,
          planId: plan.id,
          targetId: target.id,
          whyRequired:
            operation === 'destroy'
              ? 'Destroying a target is irreversible and is never covered by a daily-driver authorization.'
              : 'This operation changes what is running on this machine, and no daily-driver authorization covers it yet.',
          requestedAt: nowIso(),
          expiresAt: new Date(Date.now() + 24 * 3_600_000).toISOString(),
          decision: {
            kind: 'infrastructure_plan',
            expectedInstanceId: instanceId,
            expectedDigest: plan.digest.value,
          },
          currentDigest: plan.digest,
        }
        this.db.approvals[approvalId] = approval
        plan.approvalId = approvalId
        const inst = this.requireInstance(instanceId)
        inst.attention.push({
          id: nextId(this.db, 'attn'),
          instanceId,
          title: 'One approval is waiting',
          detail: `${titles[operation]} needs your confirmation.`,
          severity: 'action_needed',
          createdAt: nowIso(),
          read: false,
          acknowledged: false,
          actionRoute: `/approvals/${approvalId}`,
        })
        inst.health = 'attention_needed'
      }
      this.persist()
      return plan
    },

    getPlan: async (instanceId, planId) => {
      await this.lat()
      this.guard()
      const extras = this.refreshExtras()
      const plan = this.db.plans[planId] ?? extras.plans.find((p) => p.id === planId)
      if (!plan || plan.instanceId !== instanceId) {
        throw new ClientError('http', `Plan not found: ${planId}`, { status: 404 })
      }
      return plan
    },

    listPlans: async (instanceId) => {
      await this.lat()
      this.guard()
      const extras = this.refreshExtras()
      return [...Object.values(this.db.plans), ...extras.plans]
        .filter((p) => p.instanceId === instanceId)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    },

    runPlan: (planId, input) => this.runPlanImpl(planId, input),

    getAuthorization: async (instanceId) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const extras = this.refreshExtras()
      const grant = this.db.authorizations[instanceId] ?? extras.authorizations[instanceId] ?? null
      if (grant && grant.status === 'active' && grant.expiresAt && new Date(grant.expiresAt).getTime() < Date.now()) {
        grant.status = 'expired'
      }
      return grant
    },

    proposeAuthorization: async (instanceId) => {
      await this.lat()
      this.guard()
      const target = this.viewInfraTarget(instanceId)
      if (!target.available) {
        throw new ClientError('unavailable', 'Authorization requires a verified target')
      }
      const grant: AuthorizationGrant = {
        id: nextId(this.db, 'authz'),
        instanceId,
        targetId: target.id,
        status: 'proposed',
        covers: ['observe', 'validate', 'health_check', 'start', 'stop', 'restart'],
        doesNotCover: [
          'Destroy the virtual machine',
          'Change target identity',
          'Change network scope',
          'Expand filesystem scope',
          'Broaden terminal access',
          'Run an unreviewed arbitrary command',
        ],
        createdAt: nowIso(),
        expiresAt: new Date(Date.now() + 24 * 3_600_000).toISOString(),
      }
      this.db.authorizations[instanceId] = grant
      const approvalId = nextId(this.db, 'appr')
      this.db.approvals[approvalId] = {
        id: approvalId,
        instanceId,
        kind: 'authorization_grant',
        title: 'Grant daily-driver authorization',
        operationType: 'Authorization · daily-driver',
        risk: 'medium',
        status: 'pending',
        scope: [
          `Target: ${target.name}`,
          'Covers: observe, validate, health check, start, graceful stop, restart',
          'Expires after 24 hours',
        ],
        beforeSummary: 'Routine operations on this target each need their own approval.',
        afterSummary: 'Routine operations are covered by one expiring authorization. Destructive operations still need separate approval.',
        planDigest: fakeDigest(`authz:${grant.id}`),
        targetId: target.id,
        whyRequired: 'A daily-driver authorization changes how approvals work for this target, so granting it needs explicit confirmation.',
        requestedAt: nowIso(),
        expiresAt: new Date(Date.now() + 24 * 3_600_000).toISOString(),
        decision: {
          kind: 'authorization_grant',
          expectedInstanceId: instanceId,
          expectedDigest: fakeDigest(`authz:${grant.id}`).value,
        },
        currentDigest: fakeDigest(`authz:${grant.id}`),
      }
      this.persist()
      return grant
    },

    activateAuthorization: async (instanceId, input) => {
      await this.lat()
      this.guard()
      const grant = this.db.authorizations[instanceId]
      if (!grant) throw new ClientError('http', 'No authorization proposed for this application', { status: 404 })
      const approval = Object.values(this.db.approvals).find(
        (a) => a.kind === 'authorization_grant' && a.instanceId === instanceId && a.targetId === grant.targetId,
      )
      if (!approval || approval.id !== input.approvalId || approval.status !== 'approved') {
        throw new ClientError('http', 'The authorization approval is not approved', { status: 409 })
      }
      grant.status = 'active'
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'Daily-driver authorization granted',
        eventKind: 'authorization.grant',
        summary: 'Routine operations on homelab-dev are covered for 24 hours.',
        relatedApprovalId: approval.id,
      })
      grant.createdByReceiptId = receipt.id
      this.persist()
      return { grant, receipt }
    },

    revokeAuthorization: async (instanceId) => {
      await this.lat()
      this.guard()
      const grant = this.db.authorizations[instanceId]
      if (!grant || grant.status !== 'active') {
        throw new ClientError('http', 'No active authorization for this application', { status: 404 })
      }
      grant.status = 'revoked'
      grant.revokedAt = nowIso()
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'Daily-driver authorization revoked',
        eventKind: 'authorization.revoke',
        summary: 'The daily-driver authorization was revoked. Routine operations need individual approval again.',
      })
      grant.revokeReceiptId = receipt.id
      this.persist()
      return { grant, receipt }
    },
  }

  private async *runPlanImpl(planId: string, input?: { approvalId?: string }): AsyncGenerator<PlanProgressEvent> {
      const behavior = getActiveBehavior()
      const extras = this.refreshExtras()
      const plan = this.db.plans[planId] ?? extras.plans.find((p) => p.id === planId)
      if (!plan) throw new ClientError('http', `Plan not found: ${planId}`, { status: 404 })
      if (plan.requiresApproval && plan.state !== 'approved') {
        if (input?.approvalId) {
          const approval = this.db.approvals[input.approvalId] ?? extras.approvals.find((a) => a.id === input.approvalId)
          if (!approval || approval.status !== 'approved') {
            throw new ClientError('http', 'The linked approval is not approved', { status: 409 })
          }
          plan.state = 'approved'
        } else {
          throw new ClientError('http', 'This plan requires approval before it can run', { status: 409 })
        }
      }
      this.guard()
      const opId = nextId(this.db, 'op')
      const op: OperationRecord = {
        id: opId,
        instanceId: plan.instanceId,
        kind: 'infrastructure_plan',
        title: plan.title,
        state: 'running',
        stageLabel: 'Starting',
        progressPercent: 0,
        startedAt: nowIso(),
        updatedAt: nowIso(),
        canPause: false,
        canCancel: plan.operation !== 'destroy',
        log: [],
        relatedPlanId: plan.id,
      }
      this.db.operations[opId] = op
      plan.state = 'running'
      this.persist()
      yield { type: 'state', planId: plan.id, state: 'running' }

      const total = plan.steps.length
      for (let i = 0; i < total; i++) {
        const step = plan.steps[i]
        op.stageLabel = step.title
        op.updatedAt = nowIso()
        yield { type: 'step', planId: plan.id, stepIndex: i, stepState: 'running' }
        const line = `$ ${step.detail}`
        op.log.push(line)
        yield { type: 'log', planId: plan.id, line }
        await sleep(300 + Math.round(this.tick() * 400))
        if (behavior?.infraPlan === 'failed' && i === Math.max(1, total - 2)) {
          const errLine = `error: ${step.title.toLowerCase()} failed — simulated failure`
          op.log.push(errLine)
          op.state = 'failed'
          op.error = 'Simulated failure injected by the active scenario.'
          op.updatedAt = nowIso()
          plan.state = 'failed'
          this.persist()
          yield { type: 'log', planId: plan.id, line: errLine }
          yield { type: 'error', planId: plan.id, message: op.error }
          return
        }
        op.log.push(`ok: ${step.title.toLowerCase()}`)
        op.progressPercent = Math.round(((i + 1) / total) * 90)
        yield { type: 'step', planId: plan.id, stepIndex: i, stepState: 'validated' }
        yield { type: 'log', planId: plan.id, line: `ok: ${step.title.toLowerCase()}` }
      }

      // Apply the plan's effect to infrastructure truth.
      const base = this.db.infraTargets[plan.instanceId]
      if (base) {
        switch (plan.operation) {
          case 'create_or_update':
            if (base.vm.state === 'not_defined') {
              base.vm = { state: 'running', since: nowIso() }
              base.ssh = { state: 'not_checked', detail: 'SSH has not been checked since creation.' }
              base.health = { state: 'not_checked' }
            }
            break
          case 'start':
            base.vm = { state: 'running', since: nowIso() }
            base.ssh = { state: 'ready', detail: 'SSH answered after start.' }
            base.health = { state: 'not_checked' }
            break
          case 'stop':
            base.vm = { state: 'stopped', since: nowIso() }
            base.ssh = { state: 'unavailable_vm_stopped', detail: 'SSH is unavailable while the virtual machine is stopped.' }
            base.health = { state: 'not_checked' }
            break
          case 'restart':
            base.vm = { state: 'running', since: nowIso() }
            base.ssh = { state: 'ready' }
            base.health = { state: 'not_checked' }
            break
          case 'destroy':
            base.available = false
            base.unavailableReason = 'The virtual machine was destroyed. Register a new target to continue.'
            base.vm = { state: 'unavailable' }
            base.ssh = { state: 'not_checked' }
            base.health = { state: 'unavailable' }
            break
          case 'health_check':
            base.health = { state: 'healthy', checkedAt: nowIso(), detail: 'All checks passed.' }
            break
          case 'observe':
          case 'validate':
            break
        }
      }

      op.state = 'validating'
      op.stageLabel = 'Validating'
      yield { type: 'state', planId: plan.id, state: 'validating' }
      await sleep(250)
      const readOnly = plan.operation === 'observe' || plan.operation === 'validate' || plan.operation === 'health_check'
      plan.state = readOnly ? 'completed_without_change' : 'validated'
      const receipt = this.makeReceipt({
        instanceId: plan.instanceId,
        actionName: receiptNameForPlan(plan),
        eventKind: `infrastructure.${plan.operation}`,
        result: readOnly ? 'completed_without_change' : 'validated',
        summary: receiptSummaryForPlan(plan),
        planDigest: plan.digest,
        relatedPlanId: plan.id,
        relatedApprovalId: plan.approvalId,
        relatedOperationId: opId,
        beforeSummary: plan.beforeSummary,
        afterSummary: plan.afterSummary,
      })
      plan.receiptId = receipt.id
      if (!this.db.plans[plan.id]) this.db.plans[plan.id] = plan
      op.state = plan.state
      op.progressPercent = 100
      op.updatedAt = nowIso()
      op.relatedReceiptId = receipt.id
      this.persist()
      yield { type: 'done', planId: plan.id, receipt }
  }

  // ── orchestration ────────────────────────────────────────────────────────────

  orchestration: StatePortClient['orchestration'] = {
    canStop: true,
    canRejectReview: true,
    getCurrent: async (instanceId) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      const behavior = getActiveBehavior()
      const capability = inst.capabilities.find((c) => c.id === 'cto_orchestration')
      if (behavior?.orchestration === 'unavailable' || capability?.status === 'unavailable') {
        throw new ClientError('unavailable', 'Orchestration state is unavailable for this application', {
          detail: 'Exact governed state could not be loaded. Execution controls are inactive.',
        })
      }
      const extras = this.refreshExtras()
      return this.db.orchestration[instanceId] ?? extras.orchestration[instanceId] ?? null
    },

    getView: async (instanceId) => {
      const session = await this.orchestration.getCurrent(instanceId)
      const behavior = getActiveBehavior()
      if (behavior?.orchestration === 'backend_unavailable') {
        // Mirrors the production typed refusal: no governed backend is
        // configured, so the UI must show an unavailable state, not an
        // active orchestration offer that always refuses.
        return {
          session,
          backendId: null,
          providerExecution: false,
          canonicalStateEffect: 'none',
          backendAvailability: {
            status: 'unavailable' as const,
            code: 'goal_backend_unavailable',
            message:
              'Governed execution is unavailable: no execution backend is configured on this host. Nothing can be prepared, executed, reviewed, or closed, and no result is fabricated.',
            nextAction:
              'No operator action enables execution here. Wait for a StatePort release that configures a governed execution backend; turning orchestration off stays available.',
          },
        }
      }
      // The mock simulates a working backend: available, explicitly labelled
      // test-only, and never provider execution.
      return {
        session,
        backendId: 'mock',
        providerExecution: false,
        canonicalStateEffect: 'none',
        backendAvailability: { status: 'available' as const, backendId: 'mock', testOnly: true },
      }
    },

    prepareSlice: async (instanceId, input) => {
      await this.lat()
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      if (getActiveBehavior()?.orchestration === 'backend_unavailable') {
        throw new ClientError('http', 'the governed goal operation was refused', {
          status: 409,
          code: 'goal_backend_unavailable',
          detail: 'No execution backend is configured on this host.',
        })
      }
      const session: OrchestrationSession = {
        id: nextId(this.db, 'orch'),
        instanceId,
        objective: input.objective,
        mode: input.mode,
        stage: 'review_base',
        state: 'prepared',
        baseIdentity: inst.repository
          ? { ...inst.repository }
          : { name: inst.name, branch: 'main', revision: 'unknown', clean: true },
        scope: ['README.md', 'notes/pilot-notes.md'],
        permissions: ['Read project files', 'Draft file changes for review'],
        budget: { maxOperations: 6, maxMinutes: 30, usedOperations: 0, usedMinutes: 0 },
        implementer: 'Assistant (orchestration)',
        reviewer: 'You',
        createdAt: nowIso(),
        updatedAt: nowIso(),
      }
      this.db.orchestration[instanceId] = session
      this.persist()
      return session
    },

    approve: async (sessionId) => {
      await this.lat()
      this.guard()
      const session = this.requireOrchestration(sessionId)
      if (session.state !== 'prepared') {
        throw new ClientError('http', `Slice cannot be approved from state “${session.state}”`, { status: 409 })
      }
      session.state = 'approved'
      session.stage = 'run'
      session.updatedAt = nowIso()
      this.persist()
      return session
    },

    run: (sessionId) => this.runOrchestrationImpl(sessionId),

    submitReview: async (sessionId, input) => {
      await this.lat()
      this.guard()
      const session = this.requireOrchestration(sessionId)
      if (session.state !== 'applied' || session.stage !== 'review_result') {
        throw new ClientError('http', 'Nothing to review yet', { status: 409 })
      }
      session.state = input.accepted ? 'human_accepted' : 'rejected'
      session.stage = 'close'
      if (input.notes) session.resultSummary = `${session.resultSummary ?? ''} Review notes: ${input.notes}`.trim()
      session.updatedAt = nowIso()
      this.persist()
      return session
    },

    close: async (sessionId) => {
      await this.lat()
      this.guard()
      const session = this.requireOrchestration(sessionId)
      if (session.stage !== 'close') {
        throw new ClientError('http', 'The slice must be reviewed before it can close', { status: 409 })
      }
      session.stage = 'receipt'
      session.updatedAt = nowIso()
      const receipt = this.makeReceipt({
        instanceId: session.instanceId,
        actionName: 'Orchestration slice closed',
        eventKind: 'orchestration.close',
        result: session.state === 'human_accepted' ? 'human_accepted' : 'rejected',
        summary: `Bounded slice “${session.objective}” closed${session.state === 'human_accepted' ? ' and accepted' : ' without acceptance'}. Orchestration stopped — nothing continues in the background.`,
      })
      session.receiptId = receipt.id
      this.persist()
      return { session, receipt }
    },

    stop: async (sessionId) => {
      await this.lat()
      this.guard()
      const session = this.requireOrchestration(sessionId)
      if (session.state === 'running') {
        session.state = 'cancelled'
        session.stage = 'close'
        session.updatedAt = nowIso()
        this.persist()
      }
      return session
    },
  }

  private async *runOrchestrationImpl(sessionId: string): AsyncGenerator<PlanProgressEvent> {
      const session = this.requireOrchestration(sessionId)
      if (session.state !== 'approved') {
        throw new ClientError('http', `Slice cannot run from state “${session.state}”`, { status: 409 })
      }
      this.guard()
      const opId = nextId(this.db, 'op')
      const op: OperationRecord = {
        id: opId,
        instanceId: session.instanceId,
        kind: 'orchestration_run',
        title: session.objective,
        state: 'running',
        stageLabel: 'Inspecting base',
        progressPercent: 0,
        startedAt: nowIso(),
        updatedAt: nowIso(),
        canPause: false,
        canCancel: true,
        log: [],
      }
      this.db.operations[opId] = op
      session.state = 'running'
      session.updatedAt = nowIso()
      this.persist()
      yield { type: 'state', planId: session.id, state: 'running' }
      const lines = [
        'inspecting base identity … ok',
        'reading README.md … ok',
        'drafting change proposal … ok',
        'running nix flake check … ok',
        'compiling result summary … ok',
      ]
      for (let i = 0; i < lines.length; i++) {
        await sleep(280 + Math.round(this.tick() * 300))
        op.log.push(lines[i])
        op.progressPercent = Math.round(((i + 1) / lines.length) * 100)
        op.updatedAt = nowIso()
        session.budget.usedOperations += 1
        yield { type: 'log', planId: session.id, line: lines[i] }
        yield { type: 'step', planId: session.id, stepIndex: i, stepState: 'validated' }
      }
      session.state = 'applied'
      session.stage = 'review_result'
      session.resultSummary = 'Inspection completed. The drafted change and the check results are ready for your review.'
      session.updatedAt = nowIso()
      op.state = 'applied'
      op.stageLabel = 'Awaiting review'
      const receipt = this.makeReceipt({
        instanceId: session.instanceId,
        actionName: 'Orchestration run completed',
        eventKind: 'orchestration.run',
        summary: `Bounded slice “${session.objective}” ran within budget (${session.budget.usedOperations}/${session.budget.maxOperations} operations).`,
        relatedOperationId: opId,
      })
      this.persist()
      yield { type: 'done', planId: session.id, receipt }
  }

  private requireOrchestration(sessionId: string): OrchestrationSession {
    const extras = this.refreshExtras()
    const session =
      Object.values(this.db.orchestration).find((s) => s.id === sessionId) ??
      Object.values(extras.orchestration).find((s) => s.id === sessionId)
    if (!session) throw new ClientError('http', `Orchestration session not found: ${sessionId}`, { status: 404 })
    return session
  }

  // ── recovery ─────────────────────────────────────────────────────────────────

  recovery: StatePortClient['recovery'] = {
    getBackupState: async (instanceId) => {
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      const behavior = getActiveBehavior()
      if (behavior?.backupDue && inst.recovery.state !== 'not_configured') {
        return { ...inst.recovery, state: 'due', detail: 'Backup interval is 24 hours.' }
      }
      return inst.recovery
    },
    runBackup: async (instanceId) => {
      await this.lat()
      await this.lat()
      this.guard()
      const inst = this.requireInstance(instanceId)
      inst.recovery = {
        state: 'current',
        lastBackupAt: nowIso(),
        nextDueAt: new Date(Date.now() + inst.settings.backup.intervalHours * 3_600_000).toISOString(),
      }
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'Backup completed',
        eventKind: 'recovery.backup',
        summary: 'Application data backed up locally.',
      })
      inst.recovery.lastReceiptId = receipt.id
      inst.attention = inst.attention.filter((a) => !a.title.toLowerCase().includes('backup'))
      if (inst.health === 'attention_needed' && inst.attention.length === 0) inst.health = 'ready'
      this.persist()
      return { recovery: inst.recovery, receipt }
    },
    getStatus: async () => {
      throw new ClientError(
        'unavailable',
        'Governed restore requires the connected StatePort recovery service',
      )
    },
    planRestore: async () => {
      throw new ClientError(
        'unavailable',
        'Governed restore cannot be simulated as durable recovery',
      )
    },
    approveRestore: async () => {
      throw new ClientError(
        'unavailable',
        'Governed restore approval requires a connected operator service',
      )
    },
    applyRestore: async () => {
      throw new ClientError(
        'unavailable',
        'Governed restore apply requires a connected operator service',
      )
    },
  }

  // ── operations ───────────────────────────────────────────────────────────────

  operations: StatePortClient['operations'] = {
    list: async (): Promise<OperationRecord[]> => {
      await this.lat()
      this.guard()
      const extras = this.refreshExtras()
      return [...Object.values(this.db.operations), ...extras.operations].sort((a, b) =>
        b.startedAt.localeCompare(a.startedAt),
      )
    },
    get: async (operationId) => {
      await this.lat()
      this.guard()
      const extras = this.refreshExtras()
      const op = this.db.operations[operationId] ?? extras.operations.find((o) => o.id === operationId)
      if (!op) throw new ClientError('http', `Operation not found: ${operationId}`, { status: 404 })
      return op
    },
    pause: async (operationId) => {
      await this.lat()
      this.guard()
      const op = this.db.operations[operationId]
      if (!op) throw new ClientError('http', `Operation not found: ${operationId}`, { status: 404 })
      if (!op.canPause) throw new ClientError('http', 'This operation does not support pause', { status: 409 })
      if (op.state === 'running') {
        op.state = 'paused'
        op.updatedAt = nowIso()
        this.persist()
      }
      return op
    },
    cancel: async (operationId) => {
      await this.lat()
      this.guard()
      const op = this.db.operations[operationId]
      if (!op) throw new ClientError('http', `Operation not found: ${operationId}`, { status: 404 })
      if (!op.canCancel) throw new ClientError('http', 'This operation cannot be cancelled safely', { status: 409 })
      if (op.state === 'running' || op.state === 'paused' || op.state === 'queued') {
        op.state = 'cancelled'
        op.updatedAt = nowIso()
        this.persist()
      }
      return op
    },
  }

  // ── scenario lab (dev) ───────────────────────────────────────────────────────

  scenario: StatePortClient['scenario'] = {
    list: async () => SCENARIOS.map((s) => ({ id: s.id as ScenarioId, label: s.label, group: s.group })),
    getActive: async () => useScenarioStore.getState().active,
    setActive: async (id) => {
      useScenarioStore.getState().setActive(id)
      this.extras = emptyExtras()
    },
    resetMockState: async () => {
      clearMockStorage()
      this.db = buildSeed(this.nowMs())
      this.terminalSessions.clear()
      this.terminalListeners.clear()
      this.terminalInputBuffers.clear()
      this.runRecords.clear()
      this.contextLifecycles.clear()
      this.settingsRevisions.clear()
      this.settingsHistory = []
      this.extras = emptyExtras()
      this.persist()
      this.flush()
    },
  }

  // ── governed execution runs (additive domain) ────────────────────────────────

  runs: StatePortClient['runs'] = {
    listActions: async (instanceId) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      return [
        {
          id: 'act_validate',
          instanceId,
          title: 'Validate configuration',
          description: 'Run the application\'s validation checks and record a receipt.',
          engineIds: [],
          formatVersion: 'stateport.application-action/v1',
          inputSchema: { type: 'object', additionalProperties: false },
          outputSchema: { type: 'object' },
          contextPolicy: { mode: 'bounded-eager' },
          requiredCapabilities: ['nonInteractiveExecution'],
          optionalCapabilities: [],
          mutationPolicy: 'none',
          networkPolicy: 'disabled',
          toolPolicy: 'declared_only',
          timeoutSeconds: 30,
          budgetDefaults: { token: 1000, seconds: 30 },
          validationPolicy: { command: 'python3 scripts/validate_repo.py' },
          supportedEngineDegradations: [],
          expectedEvidenceArtifacts: ['execution/result.json'],
        },
        {
          id: 'act_update_sample',
          instanceId,
          title: 'Update sample preference',
          description: 'Prepare a typed sample proposal without granting the engine canonical write access.',
          engineIds: [],
          formatVersion: 'stateport.application-action/v1',
          inputSchema: {
            type: 'object',
            properties: { value: { type: 'string' } },
            required: ['value'],
            additionalProperties: false,
          },
          outputSchema: { type: 'object', required: ['stateChangeProposals'] },
          contextPolicy: { mode: 'bounded-eager' },
          requiredCapabilities: ['nonInteractiveExecution', 'structuredOutput'],
          optionalCapabilities: [],
          mutationPolicy: 'propose_only',
          networkPolicy: 'disabled',
          toolPolicy: 'declared_only',
          timeoutSeconds: 30,
          budgetDefaults: { token: 1000, seconds: 30 },
          validationPolicy: { command: 'python3 scripts/validate_repo.py' },
          supportedEngineDegradations: [],
          expectedEvidenceArtifacts: ['execution/result.json', 'mutation/proposal.json'],
        },
      ]
    },
    listEngines: async () => {
      await this.lat()
      this.guard()
      return [
        {
          id: 'synthetic',
          label: 'synthetic',
          kind: 'synthetic-action',
          availability: 'available',
          available: true,
          formatVersion: 'stateport.execution-engine/v1',
          adapterId: 'synthetic-action',
          adapterVersion: '1.0.0',
          installedVersion: 'local',
          authenticationRouteClass: 'local_operator',
          capabilities: {
            nonInteractiveExecution: 'supported',
            structuredOutput: 'supported',
          },
          modelIdentity: 'synthetic/local-alpha',
          productionEligible: false,
          limitations: ['Deterministic fixture; production-ineligible.'],
        },
        {
          id: 'codex',
          label: 'codex',
          kind: 'codex-cli',
          availability: 'environment_gated',
          available: false,
          unavailableReason: 'Live execution remains gated until an operator-authenticated route is explicitly available.',
          formatVersion: 'stateport.execution-engine/v1',
          adapterId: 'codex-cli',
          adapterVersion: 'unverified',
          installedVersion: 'unverified',
          authenticationRouteClass: 'operator_authenticated_unverified',
          capabilities: {} as Record<string, string>,
          modelIdentity: 'unknown',
          productionEligible: false,
          limitations: ['Live execution remains gated until an operator-authenticated route is explicitly available.'],
        },
      ]
    },
    getHistory: async (instanceId) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      return [...this.runRecords.values()]
        .filter((r) => r.instanceId === instanceId)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    },
    prepare: async (instanceId, input) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      if (input.engineId !== 'synthetic') {
        throw new ClientError('http', `Engine not available: ${input.engineId}`, { status: 409 })
      }
      if (!['act_validate', 'act_update_sample'].includes(input.actionId)) {
        throw new ClientError('http', 'Action is not declared by this application', {
          status: 400,
          code: 'operation_failed',
        })
      }
      this.runSeq += 1
      const now = nowIso()
      const run: RunRecord = {
        id: `run_${String(this.runSeq).padStart(4, '0')}`,
        instanceId,
        actionId: input.actionId,
        engineId: input.engineId,
        state: 'awaiting_approval',
        status: 'awaiting_approval',
        lifecycleState: 'AWAITING_RUN_APPROVAL',
        lifecycleVersion: 'stateport.run-lifecycle/v1',
        formatVersion: 'stateport.governed-action-run/v1',
        revision: 2,
        inputs: input.inputs,
        runSpecDigest: fakeDigest(`${instanceId}:${input.actionId}:${this.runSeq}:spec`),
        runSpec: {
          runId: `run_${String(this.runSeq).padStart(4, '0')}`,
          instance: { id: instanceId, sourceRevision: fakeHex(`${instanceId}:source`, 40) },
          backend: { id: 'synthetic', adapter: { id: 'synthetic-action', version: '1.0.0' } },
          budgets: { token: 1000, seconds: 30 },
          sandbox: { profile: 'read-only' },
        },
        negotiation: {
          formatVersion: 'stateport.capability-negotiation/v1',
          accepted: ['nonInteractiveExecution'],
          rejected: [],
          degraded: [],
          acceptedRun: true,
          adapter: { id: 'synthetic-action', version: '1.0.0' },
        },
        approvalRequired: true,
        events: [
          { type: 'state_transition', from: 'requested', to: 'planned', actor: 'stateport', at: now },
          { type: 'state_transition', from: 'planned', to: 'awaiting_approval', actor: 'stateport', at: now },
        ],
        createdAt: now,
        updatedAt: now,
      }
      this.runRecords.set(run.id, run)
      return run
    },
    transition: async (runId, operation, input) => {
      await this.lat()
      this.guard()
      const run = this.runRecords.get(runId)
      if (!run) throw new ClientError('http', `Run not found: ${runId}`, { status: 404 })
      if (run.instanceId !== input.expectedInstanceId) {
        throw new ClientError('http', 'Run belongs to a different application', { status: 409 })
      }
      if (run.revision !== input.expectedRevision) {
        throw new ClientError('http', 'The local operation failed', {
          status: 400,
          code: 'operation_failed',
        })
      }
      const previousStatus = run.status
      const refuse = (): never => {
        throw new ClientError('http', 'The local operation failed', {
          status: 400,
          code: 'operation_failed',
        })
      }
      if (operation === 'approve') {
        if (run.status !== 'awaiting_approval') refuse()
        run.status = 'approved'
        run.lifecycleState = 'APPROVED'
        run.state = 'approved'
      } else if (operation === 'execute') {
        if (run.status !== 'approved') refuse()
        if (run.actionId === 'act_update_sample') {
          const proposalId = `proposal_${run.id}`
          run.status = 'state_change_proposed'
          run.lifecycleState = 'PROPOSAL_CREATED'
          run.state = 'proposed'
          run.proposal = {
            formatVersion: 'stateport.state-change-proposal/v1',
            proposalId,
            preStateDigest: fakeDigest(`${run.id}:before`).value,
            operations: [
              {
                operation: 'replace',
                path: 'state/SAMPLE.yaml',
                value: run.inputs.value,
              },
            ],
          }
          run.proposalDigest = fakeDigest(`${run.id}:proposal`)
          run.result = {
            canonicalStateUnchanged: true,
            stateChangeProposals: [run.proposal],
          }
        } else {
          run.status = 'completed'
          run.lifecycleState = 'CLOSED'
          run.state = 'completed_without_change'
          run.result = { canonicalStateUnchanged: true }
        }
      } else if (operation === 'proposal-approve') {
        if (run.status !== 'state_change_proposed') refuse()
        run.status = 'state_change_approved'
        run.lifecycleState = 'AWAITING_PROPOSAL_APPROVAL'
        run.state = 'approved'
      } else if (operation === 'proposal-reject') {
        if (run.status !== 'state_change_proposed') refuse()
        run.status = 'state_change_rejected'
        run.lifecycleState = 'CLOSED'
        run.state = 'rejected'
      } else if (operation === 'apply') {
        if (run.status !== 'state_change_approved') refuse()
        const proposal = run.proposal
        if (!proposal) {
          throw new ClientError('http', 'The local operation failed', {
            status: 400,
            code: 'operation_failed',
          })
        }
        run.status = 'applied'
        run.lifecycleState = 'CLOSED'
        run.state = 'applied'
        run.postApplyValidation = {
          status: 'passed',
          commandDigest: fakeDigest(`${run.id}:validation`).value,
        }
        run.receipt = {
          formatVersion: 'stateport.application-apply-receipt/v1',
          proposalId: proposal.proposalId,
          preStateDigest: proposal.preStateDigest,
          postStateDigest: fakeDigest(`${run.id}:after`).value,
          validation: 'passed',
        }
        const closureReceipt = this.makeReceipt({
          instanceId: run.instanceId,
          actionName: 'Governed run applied',
          eventKind: 'governed_run.apply',
          actor: 'system',
          result: 'applied',
          summary: 'StatePort applied the exact approved governed-run proposal.',
          beforeSummary: 'Canonical application state matched the approved base.',
          afterSummary: 'The approved transaction was applied and locally validated.',
        })
        run.receiptId = closureReceipt.id
        run.closureReceipt = {
          receiptId: closureReceipt.id,
          claimState: {
            applied: true,
            locallyValidated: true,
            humanAccepted: false,
            remotelyAccepted: false,
          },
        }
      } else {
        if (!run.status || !['awaiting_approval', 'approved', 'prepared', 'running', 'cancelling', 'interrupted'].includes(run.status)) {
          refuse()
        }
        run.status = 'cancelled'
        run.lifecycleState = 'CANCELLED'
        run.state = 'cancelled'
      }
      run.revision += 1
      run.updatedAt = nowIso()
      run.events = [
        ...(run.events ?? []),
        {
          type: 'state_transition',
          from: previousStatus,
          to: run.status,
          actor: 'stateport',
          at: run.updatedAt,
        },
      ]
      this.persist()
      return run
    },
    getBundle: async (runId) => {
      await this.lat()
      this.guard()
      const run = this.runRecords.get(runId)
      if (!run) throw new ClientError('http', `Run not found: ${runId}`, { status: 404 })
      if (!run.status || ['requested', 'planned', 'awaiting_approval', 'approved', 'preparing', 'prepared', 'running'].includes(run.status)) {
        throw new ClientError('http', 'Run has no immutable RunBundle', { status: 400, code: 'operation_failed' })
      }
      const contentDigest = fakeDigest(`${runId}:bundle`)
      return {
        runId,
        applied: false,
        formatVersion: 'stateport.run-bundle/v1',
        contentDigest,
        fileCount: 18,
        verified: true,
        events: [],
        receiptIds: run.receiptId ? [run.receiptId] : [],
      }
    },
    getStateBench: async (runId) => {
      await this.lat()
      this.guard()
      const run = this.runRecords.get(runId)
      if (!run) throw new ClientError('http', `Run not found: ${runId}`, { status: 404 })
      if (!run.status || ['requested', 'planned', 'awaiting_approval', 'approved', 'preparing', 'prepared', 'running'].includes(run.status)) {
        throw new ClientError('http', 'Run has no StateBench evidence', { status: 400, code: 'operation_failed' })
      }
      const statePreserved = run.status !== 'applied'
      return {
        subjectId: runId,
        applied: false,
        row: {
          formatVersion: 'statebench.run-bundle-row/v1',
          integrityStatus: 'verified',
          authoritative: false,
          producerClaimsTrusted: false,
          bundleDigest: fakeDigest(`${runId}:bundle`),
          runId,
          applicationId: run.instanceId,
          engineId: run.engineId,
          adapterId: 'synthetic-action',
          status: run.status,
          statePreserved,
          capabilityDegradations: [],
          acceptedRun: true,
          usageAvailable: null,
          latencyMs: null,
          unauthorizedMutations: 0,
          bundleFileCount: 18,
        },
        state: run.state,
        checks: [
          { id: 'bundle_integrity', title: 'RunBundle integrity', state: 'validated' },
          {
            id: 'state_preservation',
            title: 'Canonical state preservation',
            state: statePreserved ? 'validated' : 'failed',
          },
          { id: 'capability_negotiation', title: 'Capability negotiation', state: 'validated' },
          { id: 'unauthorized_mutations', title: 'Unauthorized mutations', state: 'validated', detail: 'None recorded.' },
        ],
      }
    },
  }

  // ── sanctioned execution-host control-plane proxy ──────────────────────────
  // The mock NEVER fabricates live container state: it reports the honest
  // unavailable surface (no daemon in the mock adapter) so the UI shows its
  // real state.

  executionHost: StatePortClient['executionHost'] = {
    status: async () => {
      await this.lat()
      return {
        status: 'unavailable',
        reason: 'execution_socket_not_configured',
        detail:
          'The mock adapter has no execution host; the sanctioned proxy is unavailable.',
        grantBound: false,
      }
    },
    listWorkloads: async () => {
      await this.lat()
      return { accepted: false, refusal: { reason: 'execution_unavailable' } }
    },
    listReceipts: async () => {
      await this.lat()
      return { receipts: [] }
    },
    workloadStatus: async () => {
      await this.lat()
      return { accepted: false, refusal: { reason: 'execution_unavailable' } }
    },
    workloadLogs: async () => {
      await this.lat()
      return { accepted: false, refusal: { reason: 'execution_unavailable' } }
    },
    createDefaultWorkload: async () => {
      await this.lat()
      return { accepted: false, refusal: { reason: 'execution_unavailable' } }
    },
    startWorkload: async () => {
      await this.lat()
      return { accepted: false, refusal: { reason: 'execution_unavailable' } }
    },
    stopWorkload: async () => {
      await this.lat()
      return { accepted: false, refusal: { reason: 'execution_unavailable' } }
    },
    cancelWorkload: async () => {
      await this.lat()
      return { accepted: false, refusal: { reason: 'execution_unavailable' } }
    },
    removeWorkload: async () => {
      await this.lat()
      return { accepted: false, refusal: { reason: 'execution_unavailable' } }
    },
    execWorkload: async () => {
      await this.lat()
      return { accepted: false, refusal: { reason: 'execution_unavailable' } }
    },
  }

  // ── context lifecycle (additive domain) ──────────────────────────────────────

  context: StatePortClient['context'] = {
    getLifecycle: async (instanceId) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      return this.contextLifecycleFor(instanceId)
    },
    updatePreference: async (instanceId, input) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const lifecycle = this.contextLifecycleFor(instanceId)
      if (input.expectedPolicyDigest !== lifecycle.policyDigest.value) {
        throw new ClientError('http', 'Context policy changed since you loaded it — refresh and try again', { status: 409 })
      }
      lifecycle.preference = input.mode
      lifecycle.policyDigest = fakeDigest(`${instanceId}:policy:${input.mode}`)
      lifecycle.effectivePolicy.effectivePolicyDigest = lifecycle.policyDigest.value
      lifecycle.continuity.expectedPolicyDigest = lifecycle.policyDigest.value
      return lifecycle
    },
    compact: async (instanceId, input) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const lifecycle = this.contextLifecycleFor(instanceId)
      if (input.expectedContinuityDigest !== lifecycle.continuity.continuityDigest) {
        throw new ClientError('http', 'Continuity identity mismatch — compaction refused', { status: 409 })
      }
      lifecycle.segments = lifecycle.segments.filter((s) => s.pinned)
      lifecycle.storedRecordCount += 1
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'Context compacted',
        eventKind: 'context.compact',
        summary: 'Unpinned context segments compacted; continuity identity preserved.',
      })
      this.persist()
      return { lifecycle, receiptId: receipt.id, summary: 'Context compacted without touching canonical state.' }
    },
    handoff: async (instanceId, input) => {
      await this.lat()
      this.guard()
      this.requireInstance(instanceId)
      const lifecycle = this.contextLifecycleFor(instanceId)
      if (input.expectedContinuityDigest !== lifecycle.continuity.continuityDigest) {
        throw new ClientError('http', 'Continuity identity mismatch — handoff refused', { status: 409 })
      }
      lifecycle.storedRecordCount += 1
      const receipt = this.makeReceipt({
        instanceId,
        actionName: 'Context handoff created',
        eventKind: 'context.handoff',
        summary: 'A context handoff bundle was created; continuity identity preserved.',
      })
      this.persist()
      return { lifecycle, receiptId: receipt.id, summary: 'Handoff created without touching canonical state.' }
    },
  }

  // ── repository import (additive domain, for future wiring) ───────────────────

  repositoryImport: StatePortClient['repositoryImport'] = {
    listLocalCandidates: async () => {
      await this.lat()
      this.guard()
      return [
        { candidateId: 'cand_photography', displayName: 'photography-portfolio', relativeLocation: 'projects/photography-portfolio', suggestedPackageId: 'pkg_project_state' },
        { candidateId: 'cand_reading', displayName: 'reading-notes', relativeLocation: 'projects/reading-notes', suggestedPackageId: 'pkg_study_state' },
      ]
    },
    inspect: async (candidateId) => {
      await this.lat()
      this.guard()
      if (!candidateId.trim()) throw new ClientError('validation', 'A repository candidate is required')
      const candidate = (await this.repositoryImport.listLocalCandidates()).find((entry) => entry.candidateId === candidateId)
      return {
        candidateId,
        source: candidate?.relativeLocation ?? candidateId,
        inspectionDigest: fakeDigest(`inspect:${candidateId}`).value,
        branch: 'main',
        headCommit: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
        dirty: false,
        findings: [],
        mutated: false,
        template: candidateId === 'cand_reading'
          ? {
              formatVersion: 'stateport.template-adapter-match/v1',
              adapterId: 'studystate',
              applicationId: 'stateport.template.studystate',
              displayName: 'StudyState',
              description: 'An isolated StudyState learner workspace.',
              templateKind: 'studystate',
              declaredTemplateId: 'studystate',
              declaredVersion: '0.6.0',
              markerFiles: ['state/STUDYDD_MODE.yaml', 'state/STUDY_STATE.yaml'],
              requestedCapabilities: ['conversation', 'progress_dashboard', 'goal_execution'],
              trustedActionIds: ['stateport.template.studystate.inspect/v1'],
              executionTrust: 'stateport_owned_adapter_only',
              repositoryCommandsExecuted: false,
              validation: { status: 'passed', issues: [] },
            }
          : {
              formatVersion: 'stateport.template-adapter-match/v1',
              adapterId: 'projectstate-v6',
              applicationId: 'stateport.template.projectstate',
              displayName: 'ProjectState',
              description: 'An isolated ProjectState workspace.',
              templateKind: 'projectstate_v6',
              declaredTemplateId: 'projectstate',
              declaredVersion: 'projectstate-template-v6',
              markerFiles: ['PROJECT.md', 'STATE.yaml'],
              requestedCapabilities: ['conversation', 'progress_dashboard', 'goal_execution', 'workbench'],
              trustedActionIds: ['stateport.template.projectstate.inspect/v1'],
              executionTrust: 'stateport_owned_adapter_only',
              repositoryCommandsExecuted: false,
              validation: { status: 'passed', issues: [] },
            },
      }
    },
    register: async (input) => {
      await this.lat()
      this.guard()
      if (!input.approved) {
        throw new ClientError('validation', 'Repository registration requires an explicit approval')
      }
      const expected = fakeDigest(`inspect:${input.candidateId}`).value
      if (input.inspectionDigest !== expected) {
        throw new ClientError('http', 'Inspection digest mismatch — inspect the repository again before registering', { status: 409 })
      }
      const pkg = this.db.packages.find((p) => p.name === 'project-state') ?? this.db.packages[0]
      const id = nextId(this.db, 'ins').replace(/^ins_/, 'ins-')
      const conversationId = nextId(this.db, 'conv')
      const instance: ApplicationInstance = {
        id,
        name: input.name.trim() || 'Imported repository',
        packageId: pkg.id,
        packageName: pkg.name,
        packageDisplayName: pkg.displayName,
        health: 'ready',
        attention: [],
        recentActivity: [],
        settings: {
          instanceId: id,
          notificationLevel: 'inherit',
          conversation: { defaultContext: ['application', 'summary'] },
          backup: { enabled: true, intervalHours: 24 },
          terminal: {},
        },
        conversationId,
        capabilities: pkg.capabilities.map((cid) => ({ id: cid, status: 'available' as const })),
        receiptIds: [],
        recovery: { state: 'not_configured' },
        provenance: {
          source: {
            resolvedCommit: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
            resolvedTree: fakeHex(`import:${input.candidateId}:tree`, 40),
            sourceKind: 'local',
            ownership: 'user_owned_repository',
            productionEligible: false,
          },
          ownership: {
            counts: { template: 0, instance: 0, generated: 0, override: 0 },
            paths: { template: [], instance: [], generated: [], override: [] },
            truncated: { template: false, instance: false, generated: false, override: false },
          },
        },
        pinned: false,
        createdAt: nowIso(),
      }
      this.db.instances.push(instance)
      const receipt = this.makeReceipt({
        instanceId: id,
        actionName: 'Repository registered',
        eventKind: 'repository.import',
        summary: `Repository registered as ${instance.name}; no repository code was executed.`,
        relatedConversationId: conversationId,
      })
      this.addActivity({ kind: 'repository.register', title: `Repository registered: ${input.candidateId}` })
      this.persist()
      const registration: RepositoryRegistration = { instanceId: id, conversationId, receiptId: receipt.id }
      return registration
    },
    installTemplate: async (input) => this.repositoryImport.register({
      candidateId: input.candidateId,
      name: input.name,
      inspectionDigest: input.inspection.inspectionDigest,
      approved: input.approved,
    }),
  }

  // ── platform deployments / authority / updater / preview routes ──────────────
  // These surfaces project durable host state (governed deployment records,
  // the local authority store, the installed updater, and the loopback preview
  // registry). They are not simulated: the mock adapter fails closed so the
  // UI shows its honest unavailable state instead of fabricated operator data.

  platformDeployments: StatePortClient['platformDeployments'] = {
    list: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Platform deployments are not simulated', {
        detail: 'Connect the operator service to inspect governed deployment state.',
      })
    },
    get: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Platform deployments are not simulated', {
        detail: 'Connect the operator service to inspect governed deployment state.',
      })
    },
    plan: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Deployment planning is not simulated', {
        detail: 'Connect the operator service to plan a governed deployment.',
      })
    },
    apply: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Deployment apply is not simulated', {
        detail: 'Connect the operator service to apply an accepted deployment plan.',
      })
    },
    status: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Deployment observation is not simulated', {
        detail: 'Connect the operator service to observe a deployment.',
      })
    },
    logs: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Deployment logs are not simulated', {
        detail: 'Connect the operator service to collect deployment logs.',
      })
    },
    restart: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Deployment restart is not simulated', {
        detail: 'Connect the operator service to restart a deployment.',
      })
    },
    remove: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Deployment removal is not simulated', {
        detail: 'Connect the operator service to remove a deployment runtime.',
      })
    },
    planPurge: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Deployment purge planning is not simulated', {
        detail: 'Connect the operator service to plan retained-data purge.',
      })
    },
  }

  authority: StatePortClient['authority'] = {
    getIndex: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Authority index is not simulated', {
        detail: 'Connect the operator service to inspect the local authority state.',
      })
    },
    listProfiles: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Authority profiles are not simulated', {
        detail: 'Connect the operator service to inspect the local authority policy.',
      })
    },
    listGrants: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Authority grants are not simulated', {
        detail: 'Connect the operator service to inspect standing grants.',
      })
    },
    getGrant: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Authority grant detail is not simulated', {
        detail: 'Connect the operator service to inspect a standing grant.',
      })
    },
    revokeGrant: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Authority grant revocation is not simulated', {
        detail: 'Connect the operator service to revoke a grant under an owner directive.',
      })
    },
    setPaused: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Authority pause control is not simulated', {
        detail: 'Connect the operator service to pause or unpause the authority store.',
      })
    },
  }

  updater: StatePortClient['updater'] = {
    getStatus: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Installed updater status is not simulated', {
        detail: 'Connect the operator service to observe installed updater state.',
      })
    },
    getPolicy: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Installed updater policy is not simulated', {
        detail: 'Connect the operator service to observe the update policy.',
      })
    },
    getRollback: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Installed updater rollback projection is not simulated', {
        detail: 'Connect the operator service to observe the retained-predecessor rollback.',
      })
    },
    setPolicy: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Update policy mutation is not simulated', {
        detail: 'Connect the operator service to mutate the update policy through canonical authority.',
      })
    },
    planRollback: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Updater rollback planning is not simulated', {
        detail: 'Connect the operator service to plan a retained-predecessor rollback.',
      })
    },
  }

  previewRoutes: StatePortClient['previewRoutes'] = {
    list: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Preview routes are not simulated', {
        detail: 'Connect the operator service to inspect the loopback preview registry.',
      })
    },
    register: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Preview route registration is not simulated', {
        detail: 'Connect the operator service to register a loopback preview route.',
      })
    },
    revoke: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Preview route revocation is not simulated', {
        detail: 'Connect the operator service to revoke a preview route.',
      })
    },
    rewrite: async () => {
      await this.lat()
      throw new ClientError('unavailable', 'Preview route rewrite is not simulated', {
        detail: 'Connect the operator service to atomically rewrite a preview route.',
      })
    },
  }

  private contextLifecycleFor(instanceId: string): ContextLifecycle {
    let lifecycle = this.contextLifecycles.get(instanceId)
    if (!lifecycle) {
      const policyDigest = fakeDigest(`${instanceId}:policy:1`)
      const continuityDigest = fakeDigest(`${instanceId}:continuity:1`).value
      lifecycle = {
        formatVersion: 'stateport.context-lifecycle-view/v1',
        instanceId,
        policyDigest,
        effectivePolicy: {
          formatVersion: 'stateport.context-lifecycle-effective/v1',
          sourcePolicies: [
            {
              scope: 'platform',
              policyId: 'platform.default',
              digest: fakeDigest(`${instanceId}:platform-policy`).value,
            },
          ],
          unresolvedPolicyScopes: ['template', 'instance', 'backend', 'budget'],
          budget: {
            maximumInputTokens: 128_000,
            preferredInputTokens: 72_000,
          },
          compression: {
            mode: 'automatic',
            triggerRatio: 0.72,
            preserve: ['active_task', 'requirements', 'pending_work', 'exact_git_identity'],
          },
          handoff: {
            mode: 'automatic',
            triggerRatio: 0.9,
            createArtifact: true,
            requireReceipt: true,
          },
          session: {
            resumeOnlyWhen: ['instance_identity_matches', 'base_sha_matches', 'policy_digest_matches'],
          },
          contextCategories: {
            included: ['active_task', 'requirements', 'completed_work', 'pending_work', 'exact_git_identity'],
            excluded: ['provider_credentials', 'raw_terminal_transcript'],
          },
          bindingReasons: {
            'budget.maximumInputTokens': ['platform'],
            'budget.preferredInputTokens': ['platform'],
            'compression.mode': ['platform'],
            'compression.triggerRatio': ['platform'],
            'handoff.mode': ['platform'],
            'handoff.triggerRatio': ['platform'],
          },
          authorityClassification: 'operational_noncanonical',
          canonicalStateMutation: false,
          effectivePolicyDigest: policyDigest.value,
        },
        preference: 'balanced',
        availableModes: [
          { id: 'faster', label: 'Faster', description: 'Compact earlier and use a smaller context target.' },
          { id: 'balanced', label: 'Balanced', description: 'Use the candidate default context and handoff thresholds.' },
          { id: 'deeper', label: 'Deeper', description: 'Keep more relevant context when platform limits permit.' },
        ],
        rawPromptFieldsAllowed: false,
        usageDisplay: 'Approximately 3340 input tokens from the StatePort estimator; provider accounting is unavailable.',
        usage: {
          formatVersion: 'stateport.context-usage/v1',
          inputTokens: 3340,
          quality: 'estimated',
          source: 'stateport_estimator',
        },
        gitIdentity: {
          repositoryId: `repository.${fakeHex(instanceId, 32)}`,
          branch: 'main',
          baseSha: '1'.repeat(40),
          headSha: '1'.repeat(40),
          treeSha: '2'.repeat(40),
          worktreeStatusDigest: fakeDigest(`${instanceId}:worktree`).value,
          worktreeClean: true,
        },
        gitIdentityReason: null,
        continuity: {
          available: true,
          reasonCode: null,
          manualCompactAvailable: true,
          manualHandoffAvailable: true,
          continuityDigest,
          conversationId: `ctx_${instanceId}`,
          workstreamId: null,
          expectedBaseSha: '1'.repeat(40),
          expectedPolicyDigest: policyDigest.value,
        },
        storedRecordCount: 0,
        defaultsEvidence: 'candidate_not_benchmarked',
        authorityClassification: 'operational_noncanonical',
        canonicalStateMutation: false,
        segments: [
          { id: 'seg_system', kind: 'system', label: 'System instructions', tokens: 480, pinned: true },
          { id: 'seg_conversation', kind: 'conversation', label: 'Conversation so far', tokens: 2100, pinned: false },
          { id: 'seg_workspace', kind: 'workspace', label: 'Open workbench context', tokens: 760, pinned: false },
        ],
      }
      this.contextLifecycles.set(instanceId, lifecycle)
    }
    return lifecycle
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Module helpers
// ─────────────────────────────────────────────────────────────────────────────

function receiptNameForApproval(approval: Approval, decision: 'approved' | 'rejected'): string {
  const names: Record<Approval['kind'], [string, string]> = {
    infrastructure_plan: ['Infrastructure plan approved', 'Infrastructure plan rejected'],
    orchestration_run: ['Orchestration run approved', 'Orchestration run rejected'],
    authorization_grant: ['Daily-driver authorization approved', 'Daily-driver authorization rejected'],
    goal_execution: ['Goal slice approved', 'Goal slice rejected'],
    template_upgrade: ['Template upgrade approved', 'Template upgrade rejected'],
    file_write: ['File change approved', 'File change rejected'],
    capability_change: ['Capability change approved', 'Capability change rejected'],
  }
  const pair = names[approval.kind]
  return decision === 'approved' ? pair[0] : pair[1]
}

function receiptNameForPlan(plan: InfrastructurePlan): string {
  const names: Record<InfrastructureOperation, string> = {
    observe: 'Target observed',
    validate: 'Configuration validated',
    health_check: 'Health check passed',
    create_or_update: 'Virtual machine created or updated',
    start: 'Virtual machine started',
    stop: 'Virtual machine stopped',
    restart: 'Virtual machine restarted',
    destroy: 'Virtual machine destroyed',
  }
  return names[plan.operation]
}

function receiptSummaryForPlan(plan: InfrastructurePlan): string {
  switch (plan.operation) {
    case 'create_or_update':
      return 'The repository-owned virtual machine workflow completed and the target was observed.'
    case 'start':
      return 'homelab-dev started; SSH is ready. Health has not been checked yet.'
    case 'stop':
      return 'homelab-dev stopped gracefully.'
    case 'restart':
      return 'homelab-dev restarted; SSH is ready. Health has not been checked yet.'
    case 'destroy':
      return 'homelab-dev was destroyed. The target is no longer available.'
    case 'health_check':
      return 'All health checks passed on homelab-dev.'
    case 'validate':
      return 'nix flake check passed for nixos-homelab @ main.'
    case 'observe':
      return 'Target state observed and recorded.'
  }
}

function beforeSummaryFor(target: InfrastructureTarget): string {
  return `Virtual machine ${target.name} is ${target.vm.state}.`
}

function afterSummaryFor(operation: InfrastructureOperation): string {
  switch (operation) {
    case 'create_or_update':
      return 'The repository-owned virtual machine definition is applied, then the target is observed.'
    case 'start':
      return 'Virtual machine homelab-dev is running; SSH becomes ready.'
    case 'stop':
      return 'Virtual machine homelab-dev is stopped.'
    case 'restart':
      return 'Virtual machine homelab-dev is running again; SSH becomes ready.'
    case 'destroy':
      return 'Virtual machine homelab-dev no longer exists. This cannot be undone.'
    case 'health_check':
      return 'Health state is verified and timestamped.'
    case 'validate':
      return 'Configuration validity is verified and recorded.'
    case 'observe':
      return 'Current target state is recorded. Nothing changes.'
  }
}

function rollbackFor(operation: InfrastructureOperation): string {
  switch (operation) {
    case 'create_or_update':
      return 'Use the repository-owned rollback workflow; StatePort does not imply that external effects were undone.'
    case 'start':
      return 'Stop the virtual machine from Deployments. No data is changed by starting.'
    case 'stop':
      return 'Start the virtual machine again from Deployments.'
    case 'restart':
      return 'No rollback needed; a restart is self-contained.'
    case 'destroy':
      return 'There is no rollback. Recreating the target requires a fresh setup.'
    default:
      return 'Read-only operation; nothing to roll back.'
  }
}

/** Wipe persisted mock state; the next `getClient()` (or reset) re-seeds. */
export function resetMockState(): void {
  clearMockStorage()
}
