/**
 * Domain mappers — backend wire projections → our normalized domain types.
 *
 * Every backend payload is validated with the zod schemas in this file at the
 * transport boundary; unknown enum values and malformed projections FAIL
 * CLOSED (ClientError kind 'validation') rather than leaking invented data
 * into the UI. Display-metadata fields fall back to honest neutral defaults
 * only when they are purely presentational (never state, never digests).
 *
 * Format versions that the contract pins (e.g.
 * `stateport.conversation-presentation/v1`) are validated strictly.
 */
import { z } from 'zod'

import type {
  ActivityItem,
  ApplicationInstance,
  ApplicationPackage,
  ApplicationProvenance,
  Approval,
  AppSettings,
  Attachment,
  AttentionItem,
  AuthorizationGrant,
  CapabilityId,
  CapabilityState,
  CapabilityStatus,
  CatalogPackage,
  ContextLifecycle,
  Conversation,
  ConversationMessage,
  ExecutionEngine,
  GlobalSettings,
  GlobalSettingsRollbackTarget,
  GovernedAction,
  HealthState,
  InfrastructureOperation,
  InfrastructurePlan,
  InfrastructureTarget,
  InstanceHealth,
  LocalServiceStatus,
  NotificationItem,
  OperationState,
  OrchestrationSession,
  OrchestrationStage,
  PlanDigest,
  PlatformStateBenchView,
  Receipt,
  ReceiptResult,
  RepositoryCandidate,
  RepositoryInspection,
  RepositoryRegistration,
  ResolvedApplicationAdvancedControl,
  ResolvedApplicationExperience,
  ResolvedApplicationNavigation,
  ResolvedApplicationView,
  RunBundle,
  RunLifecycleState,
  RunRecord,
  RunStatus,
  SessionInfo,
  StateBenchResult,
  TerminalTarget,
  VMPowerState,
} from '../types'
import { ClientError } from '../types'
import { defaultAppSettings, defaultGlobalSettings } from '../mock/seed'
import { schemas } from '../schemas'
import { endpoints, FORMAT, TERMINAL_SUBPROTOCOL, TERMINAL_TICKET_FORMAT } from './endpoints'

// ─────────────────────────────────────────────────────────────────────────────
// Shared wire primitives
// ─────────────────────────────────────────────────────────────────────────────

/** ISO-8601 timestamp; epoch milliseconds are accepted and normalized. */
const isoTimestamp = z.union([
  z.iso.datetime(),
  z.number().transform((ms) => new Date(ms).toISOString()),
])

/** Backend digests arrive either as plain hex or `{ algorithm, value }`. */
const digestWire = z.union([
  z.string().min(8).transform((value) => ({ algorithm: 'sha256' as const, value })),
  z.object({
    algorithm: z.string().default('sha256'),
    value: z.string().min(8),
  }).transform((d) => ({ algorithm: 'sha256' as const, value: d.value })),
])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Index responses may be a bare array or wrapped (`{ items }` / `{ <name> }`). */
function indexPayload(payload: unknown, keys: string[]): unknown[] {
  if (Array.isArray(payload)) return payload
  if (isRecord(payload)) {
    for (const key of keys) {
      if (Array.isArray(payload[key])) return payload[key]
    }
  }
  throw new ClientError('validation', 'Index payload had no recognizable collection', {
    detail: `Expected an array or one of the wrapper keys: ${keys.join(', ')}`,
  })
}

function failClosed(what: string, detail?: string): never {
  throw new ClientError('validation', `Backend projection failed closed: ${what}`, { detail })
}

/**
 * Bind an optional response identity to the application-scoped request.
 * Omitting an identity is tolerated only for older index entries; an explicit
 * conflicting identity is never replaced by the request fallback.
 */
function bindInstanceIdentity(
  responseInstanceId: string | undefined,
  expectedInstanceId: string | undefined,
  subject: string,
): string | undefined {
  if (
    responseInstanceId !== undefined &&
    expectedInstanceId !== undefined &&
    responseInstanceId !== expectedInstanceId
  ) {
    failClosed(
      `${subject} instance identity "${responseInstanceId}"`,
      `expected ${expectedInstanceId}`,
    )
  }
  return responseInstanceId ?? expectedInstanceId
}

// ─────────────────────────────────────────────────────────────────────────────
// Session and platform status
// ─────────────────────────────────────────────────────────────────────────────

const sessionWire = z.object({
  session: z.string().optional(),
  authenticated: z.boolean().optional(),
  user: z.object({ id: z.string(), displayName: z.string() }).nullable().optional(),
  csrfToken: z.string().optional(),
  issuedAt: isoTimestamp.optional(),
  expiresAt: isoTimestamp.optional(),
})

export function mapSession(payload: unknown): SessionInfo {
  const wire = sessionWire.parse(payload)
  const user = wire.user ?? null
  return {
    authenticated: wire.authenticated ?? Boolean(user ?? wire.session),
    user,
    // Session timestamps are operational (noncanonical); default honestly.
    issuedAt: wire.issuedAt ?? new Date().toISOString(),
    expiresAt: wire.expiresAt,
  }
}

const statusWire = z.object({
  state: z.string().optional(),
  version: z.string().optional(),
  detail: z.string().optional(),
  endpoint: z.string().optional(),
  time: isoTimestamp.optional(),
  runtime: z
    .object({
      status: z.enum(['available', 'unavailable']),
      reason: z.string().optional(),
      detail: z.string().optional(),
      socketPath: z.string().optional(),
      socketPresent: z.boolean().optional(),
      peerPolicy: z.string().nullable().optional(),
      workerExecutionEnabled: z.boolean().optional(),
    })
    .optional(),
  actor: z
    .object({
      role: z.enum(['local_user', 'platform_operator']),
      actorId: z.string().min(1),
      platformOperationsAllowed: z.boolean(),
      statebenchInspectionAllowed: z.boolean(),
    })
    .strict()
    .optional(),
})

export function mapStatus(payload: unknown, endpoint: string): LocalServiceStatus {
  const wire = statusWire.parse(payload)
  const stateMap: Record<string, LocalServiceStatus['state']> = {
    connected: 'connected',
    ok: 'connected',
    ready: 'connected',
    degraded: 'degraded',
    offline: 'offline',
    unknown: 'unknown',
  }
  const mapped = wire.state ? stateMap[wire.state] : undefined
  if (wire.state && !mapped) failClosed(`unknown service state "${wire.state}"`)
  return {
    // A reachable status endpoint means at least a connection exists.
    state: mapped ?? 'connected',
    endpoint: wire.endpoint ?? endpoint,
    version: wire.version,
    lastContactAt: wire.time ?? new Date().toISOString(),
    detail: wire.detail,
    runtime: wire.runtime,
    actor: wire.actor,
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Capabilities (contract §16 — gating is fail-closed)
// ─────────────────────────────────────────────────────────────────────────────

const KNOWN_CAPABILITY_IDS: readonly string[] = [
  'conversation',
  'workbench',
  'file_viewer',
  'editor',
  'terminal',
  'progress_dashboard',
  'goal_execution',
  'cto_orchestration',
  'benchmark_evidence',
  'proactive_notifications',
  'backup',
  'infrastructure',
  'receipts',
]

const capabilityStatusWire = z.enum(['available', 'degraded', 'environment_gated', 'unavailable'])

/**
 * Capability lists arrive either as `[{ id, status, reason? }]` or as a
 * record `id → status`. Unknown capability IDs are dropped; unknown statuses
 * fail closed to 'unavailable' (a hidden feature is the safe failure).
 */
export function mapCapabilities(input: unknown): CapabilityState[] {
  const entries: { id: string; status: unknown; reason?: string }[] = []
  if (Array.isArray(input)) {
    for (const item of input) {
      if (isRecord(item) && typeof item.id === 'string') {
        const reasons = Array.isArray(item.reasons)
          ? item.reasons.filter((reason): reason is string => typeof reason === 'string')
          : []
        entries.push({
          id: item.id,
          status: item.status,
          reason: typeof item.reason === 'string' ? item.reason : reasons.join('; ') || undefined,
        })
      } else if (typeof item === 'string') {
        entries.push({ id: item, status: 'available' })
      }
    }
  } else if (isRecord(input)) {
    for (const [id, status] of Object.entries(input)) entries.push({ id, status })
  }
  const out: CapabilityState[] = []
  for (const entry of entries) {
    if (!KNOWN_CAPABILITY_IDS.includes(entry.id)) continue
    const status = capabilityStatusWire.safeParse(entry.status)
    out.push({
      id: entry.id as CapabilityId,
      status: status.success ? status.data : ('unavailable' satisfies CapabilityStatus),
      reason: entry.reason ?? (status.success ? undefined : `The service reported an unrecognized state for this capability.`),
    })
  }
  return out
}

/** Experience descriptor — the capability-gating source of truth. */
const experienceWire = z.object({
  formatVersion: z.string().optional(),
  applicationId: z.string().optional(),
  packageId: z.string().optional(),
  instanceId: z.string().optional(),
  instanceBinding: z.object({
    instanceId: z.string(),
    applicationId: z.string(),
    descriptorDigest: digestWire,
  }).strict().optional(),
  descriptorDigest: digestWire.optional(),
  descriptorIdentity: z.object({
    applicationId: z.string().optional(),
    descriptorDigest: digestWire.optional(),
  }).passthrough().optional(),
  capabilities: z.unknown().optional(),
  advancedControls: z.array(z.object({
    controlId: z.string(),
    label: z.string(),
    component: z.string(),
    capability: z.string(),
    order: z.number().int(),
    status: z.string().optional(),
    reasons: z.array(z.string()).optional(),
    visible: z.boolean().optional(),
  }).strict()).optional(),
  views: z.array(z.union([
    z.string(),
    z.object({
      viewId: z.string(),
      label: z.string(),
      component: z.string(),
      route: z.string(),
      capability: z.string(),
      status: z.string().optional(),
      reasons: z.array(z.string()).optional(),
      visible: z.boolean().optional(),
    }),
  ])).optional(),
  navigation: z.array(z.object({
    contributionId: z.string(),
    label: z.string(),
    viewId: z.string(),
    placement: z.string(),
    order: z.number().int(),
    visible: z.boolean().optional(),
  })).optional(),
  workbenchTools: z.array(z.string()).optional(),
})

export interface ExperienceView {
  packageId?: string
  descriptorDigest?: PlanDigest
  capabilities: CapabilityState[]
  experience?: ResolvedApplicationExperience
}

const applicationExperienceComponentWire = z.enum([
  'activity_history',
  'application_home',
  'backup_manager',
  'benchmark_evidence',
  'context_summary',
  'conversation_thread',
  'cost_summary',
  'cto_orchestration',
  'development_workbench',
  'editor_surface',
  'file_viewer',
  'goal_actions',
  'notification_feed',
  'permission_summary',
  'progress_overview',
  'receipt_list',
  'run_history',
  'state_summary',
  'terminal_surface',
  'update_manager',
])

const applicationNavigationPlacementWire = z.enum([
  'application',
  'conversation',
  'advanced',
])

function normalizedCapabilityStatus(status: unknown): CapabilityStatus {
  const parsed = capabilityStatusWire.safeParse(status)
  return parsed.success ? parsed.data : 'unavailable'
}

export function mapExperience(payload: unknown, expectedInstanceId?: string): ExperienceView {
  const wire = experienceWire.parse(payload)
  if (
    wire.formatVersion !== undefined &&
    wire.formatVersion !== FORMAT.applicationExperienceResolution
  ) {
    failClosed(
      `application experience formatVersion "${wire.formatVersion}"`,
      `expected ${FORMAT.applicationExperienceResolution}`,
    )
  }
  const boundInstanceId = wire.instanceBinding?.instanceId ?? wire.instanceId
  if (
    expectedInstanceId !== undefined &&
    boundInstanceId !== undefined &&
    boundInstanceId !== expectedInstanceId
  ) {
    failClosed(
      `application experience instance binding "${boundInstanceId}"`,
      `expected ${expectedInstanceId}`,
    )
  }
  if (
    wire.instanceBinding !== undefined &&
    wire.instanceId !== undefined &&
    wire.instanceBinding.instanceId !== wire.instanceId
  ) {
    failClosed('application experience carries contradictory instance identities')
  }

  if (
    wire.applicationId !== undefined &&
    wire.packageId !== undefined &&
    wire.applicationId !== wire.packageId
  ) {
    failClosed('application experience carries contradictory application identities')
  }
  const applicationId = wire.applicationId ?? wire.packageId
  if (
    wire.instanceBinding !== undefined &&
    applicationId !== undefined &&
    wire.instanceBinding.applicationId !== applicationId
  ) {
    failClosed('application experience instance binding carries a different application identity')
  }
  if (
    wire.descriptorIdentity?.applicationId !== undefined &&
    applicationId !== undefined &&
    wire.descriptorIdentity.applicationId !== applicationId
  ) {
    failClosed('application experience descriptor identity carries a different application identity')
  }
  const descriptorDigest =
    wire.descriptorDigest ??
    wire.descriptorIdentity?.descriptorDigest ??
    wire.instanceBinding?.descriptorDigest
  const suppliedDescriptorDigests = [
    wire.descriptorDigest,
    wire.descriptorIdentity?.descriptorDigest,
    wire.instanceBinding?.descriptorDigest,
  ].filter((value): value is PlanDigest => value !== undefined)
  if (
    suppliedDescriptorDigests.some((value) => value.value !== suppliedDescriptorDigests[0]?.value)
  ) {
    failClosed('application experience carries contradictory descriptor identities')
  }

  const views: ResolvedApplicationView[] = []
  for (const item of wire.views ?? []) {
    if (typeof item === 'string') continue
    const component = applicationExperienceComponentWire.safeParse(item.component)
    if (!component.success || !KNOWN_CAPABILITY_IDS.includes(item.capability)) continue
    const status = normalizedCapabilityStatus(item.status)
    views.push({
      viewId: item.viewId,
      label: item.label,
      component: component.data,
      declaredRoute: item.route,
      capability: item.capability as CapabilityId,
      status,
      reasons: item.reasons ?? [],
      visible: item.visible === true && (status === 'available' || status === 'degraded'),
    })
  }
  const viewIds = new Set<string>()
  for (const view of views) {
    if (viewIds.has(view.viewId)) failClosed(`application experience has duplicate view "${view.viewId}"`)
    viewIds.add(view.viewId)
  }

  const navigation: ResolvedApplicationNavigation[] = []
  const contributionIds = new Set<string>()
  for (const item of wire.navigation ?? []) {
    const placement = applicationNavigationPlacementWire.safeParse(item.placement)
    if (!placement.success || item.order < 0 || item.order > 1000) continue
    if (contributionIds.has(item.contributionId)) {
      failClosed(`application experience has duplicate navigation contribution "${item.contributionId}"`)
    }
    contributionIds.add(item.contributionId)
    navigation.push({
      contributionId: item.contributionId,
      label: item.label,
      viewId: item.viewId,
      placement: placement.data,
      order: item.order,
      visible: item.visible === true && viewIds.has(item.viewId),
    })
  }
  navigation.sort((left, right) =>
    left.order - right.order || left.contributionId.localeCompare(right.contributionId),
  )

  const advancedControls: ResolvedApplicationAdvancedControl[] = []
  const controlIds = new Set<string>()
  for (const item of wire.advancedControls ?? []) {
    if (controlIds.has(item.controlId)) {
      failClosed(`application experience has duplicate advanced control "${item.controlId}"`)
    }
    controlIds.add(item.controlId)
    const component = applicationExperienceComponentWire.safeParse(item.component)
    if (
      !component.success ||
      !KNOWN_CAPABILITY_IDS.includes(item.capability) ||
      item.order < 0 ||
      item.order > 1000
    ) {
      continue
    }
    const status = normalizedCapabilityStatus(item.status)
    const capability =
      item.component === 'receipt_list' &&
      (item.capability === 'goal_execution' || item.capability === 'cto_orchestration')
        ? 'receipts'
        : item.capability
    advancedControls.push({
      controlId: item.controlId,
      label: item.label,
      component: component.data,
      capability: capability as CapabilityId,
      order: item.order,
      status,
      reasons: item.reasons ?? [],
      visible: item.visible === true && (status === 'available' || status === 'degraded'),
    })
  }

  const capabilities = mapCapabilities(wire.capabilities)
  const addDerived = (id: CapabilityId, component: string) => {
    if (capabilities.some((capability) => capability.id === id)) return
    const control = advancedControls.find((candidate) =>
      candidate.visible &&
      (id === 'infrastructure'
        ? candidate.label.toLowerCase() === 'deployments' ||
          (wire.applicationId === 'nixos-infrastructure' && candidate.component === component)
        : candidate.component === component && candidate.capability === id),
    )
    if (!control) return
    capabilities.push({
      id,
      status: control.status,
      reason: control.reasons.join('; ') || undefined,
    })
  }
  // These are trusted declarative controls in the resolved backend
  // experience, not capabilities invented from mock data.
  addDerived('infrastructure', 'progress_overview')
  addDerived('receipts', 'receipt_list')

  advancedControls.sort((left, right) =>
    left.order - right.order || left.controlId.localeCompare(right.controlId),
  )

  return {
    packageId: applicationId,
    descriptorDigest,
    capabilities,
    experience:
      wire.formatVersion === FORMAT.applicationExperienceResolution && applicationId
        ? {
            formatVersion: FORMAT.applicationExperienceResolution,
            applicationId,
            descriptorDigest,
            views,
            navigation,
            advancedControls,
          }
        : undefined,
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Application packages (catalog) and instances
// ─────────────────────────────────────────────────────────────────────────────

const packageWire = z.object({
  id: z.string().optional(),
  applicationId: z.string().optional(),
  name: z.string().optional(),
  displayName: z.string().optional(),
  description: z.string().optional(),
  version: z.string().optional(),
  releaseStatus: z.enum(['stable', 'beta', 'experimental']).optional(),
  productionEligible: z.boolean().optional(),
  publicSafe: z.boolean().optional(),
  privacyClassification: z.string().optional(),
  reviewClassification: z.enum(['reviewed', 'community']).optional(),
  capabilities: z.unknown().optional(),
  views: z.array(z.string()).optional(),
  permissions: z
    .object({
      fileAccess: z.string().optional(),
      terminalAccess: z.string().optional(),
      networkAccess: z.string().optional(),
      dataOwnership: z.string().optional(),
    })
    .optional(),
  networkPolicy: z.string().optional(),
  dataBoundaries: z.array(z.string()).optional(),
  workbenchTools: z.array(z.string()).optional(),
  descriptorDigest: digestWire.optional(),
  packageDigest: digestWire.optional(),
  experienceDescriptorDigest: digestWire.optional(),
  applicationIdentity: z.object({
    descriptorDigest: digestWire.optional(),
    packageDigest: digestWire.optional(),
  }).optional(),
  experienceIdentity: z.object({ descriptorDigest: digestWire.optional() }).nullable().optional(),
  install: z.object({
    confirmationRequired: z.boolean().optional(),
    networkPolicy: z.string().optional(),
    reasons: z.array(z.string()).optional(),
    requestedCapabilities: z.array(z.string()).optional(),
    sourceKind: z.string().optional(),
    status: z.string().optional(),
  }).optional(),
  installRequiresApproval: z.boolean().optional(),
  installedInstanceCount: z.number().int().nonnegative().optional(),
})

export interface PackageView {
  pkg: ApplicationPackage
  descriptorDigest?: PlanDigest
  packageDigest?: PlanDigest
  experienceDescriptorDigest?: PlanDigest
  installRequiresApproval: boolean
  installAvailable: boolean
  installUnavailableReason?: string
  installedInstanceCount?: number
}

const KNOWN_WORKBENCH_TOOLS = ['overview', 'files', 'terminal', 'deployments', 'orchestration', 'receipts'] as const

export function mapPackage(payload: unknown): PackageView {
  const wire = packageWire.parse(payload)
  const id = wire.id ?? wire.applicationId
  if (!id) failClosed('application catalog entry without identity')
  const capabilities = mapCapabilities(wire.capabilities ?? wire.install?.requestedCapabilities)
  const name = wire.name ?? id
  const requested = wire.install?.requestedCapabilities ?? []
  const workbenchTools = wire.workbenchTools ?? [
    ...(requested.includes('progress_dashboard') ? ['overview'] : []),
    ...(requested.includes('file_viewer') || requested.includes('editor') ? ['files'] : []),
    ...(requested.includes('terminal') ? ['terminal'] : []),
    ...(id === 'nixos-infrastructure' ? ['deployments'] : []),
    ...(requested.includes('cto_orchestration') ? ['orchestration', 'receipts'] : []),
  ]
  const networkPolicyRaw = wire.networkPolicy ?? wire.install?.networkPolicy
  const networkPolicy: ApplicationPackage['networkPolicy'] =
    networkPolicyRaw === 'disabled' || networkPolicyRaw === 'none'
      ? 'none'
      : networkPolicyRaw === 'full'
        ? 'full'
        : networkPolicyRaw === 'restricted'
          ? 'restricted'
          : 'local_only'
  const descriptorDigest = wire.descriptorDigest ?? wire.applicationIdentity?.descriptorDigest
  const packageDigest = wire.packageDigest ?? wire.applicationIdentity?.packageDigest
  const experienceDescriptorDigest = wire.experienceDescriptorDigest ?? wire.experienceIdentity?.descriptorDigest
  const exactInstallIdentity = Boolean(descriptorDigest && packageDigest && experienceDescriptorDigest)
  const installAvailable = wire.install?.status === 'available' && exactInstallIdentity
  const backendReasons = wire.install?.reasons?.map((reason) => reason.replaceAll('_', ' ')) ?? []
  const installUnavailableReason = installAvailable
    ? undefined
    : backendReasons.length > 0
      ? backendReasons.join('; ')
      : wire.install?.status === 'available'
        ? 'The service did not provide the exact descriptor identities required for installation.'
        : 'The connected service does not offer this package for installation.'
  return {
    pkg: {
      id,
      name,
      displayName: wire.displayName ?? name,
      description: wire.description ?? '',
      version: wire.version ?? '0.0.0',
      releaseStatus: wire.releaseStatus ?? (wire.productionEligible === true ? 'stable' : 'experimental'),
      reviewClassification: wire.reviewClassification ?? 'reviewed',
      capabilities: capabilities.filter((c) => c.status !== 'unavailable').map((c) => c.id),
      views: wire.views ?? [],
      permissions: {
        fileAccess: wire.permissions?.fileAccess ?? 'Declared by the application package.',
        terminalAccess: wire.permissions?.terminalAccess ?? 'Declared by the application package.',
        networkAccess: wire.permissions?.networkAccess ?? 'Declared by the application package.',
        dataOwnership: wire.permissions?.dataOwnership ?? 'Your data stays on this machine.',
      },
      networkPolicy,
      dataBoundaries: wire.dataBoundaries ?? [
        wire.privacyClassification ? `Privacy classification: ${wire.privacyClassification}` : 'Application-owned data boundary',
      ],
      workbenchTools: workbenchTools.filter((t): t is (typeof KNOWN_WORKBENCH_TOOLS)[number] =>
        (KNOWN_WORKBENCH_TOOLS as readonly string[]).includes(t),
      ),
      productionEligible: wire.productionEligible,
      publicSafe: wire.publicSafe ?? (wire.privacyClassification === 'public_safe' ? true : undefined),
      sourceKind: wire.install?.sourceKind,
      privacyClassification: wire.privacyClassification,
    },
    descriptorDigest,
    packageDigest,
    experienceDescriptorDigest,
    // Fail closed: identity-bound installation is always review-first.
    installRequiresApproval: wire.installRequiresApproval ?? wire.install?.confirmationRequired ?? true,
    installAvailable,
    installUnavailableReason,
    installedInstanceCount: wire.installedInstanceCount,
  }
}

export function mapCatalog(payload: unknown): CatalogPackage[] {
  return indexPayload(payload, ['applications', 'items', 'packages']).map((entry) => {
    const view = mapPackage(entry)
    return {
      pkg: view.pkg,
      installedInstanceCount: view.installedInstanceCount ?? 0,
      installRequiresApproval: view.installRequiresApproval,
      installAvailable: view.installAvailable,
      installUnavailableReason: view.installUnavailableReason,
    }
  })
}

const HEALTH_MAP: Record<string, InstanceHealth> = {
  valid: 'ready',
  ready: 'ready',
  ok: 'ready',
  running: 'ready',
  attention: 'attention_needed',
  attention_needed: 'attention_needed',
  degraded: 'degraded',
  blocked: 'blocked',
  offline: 'offline',
  stopped: 'offline',
  unknown: 'offline',
  unavailable: 'blocked',
}

const PATH_BOUND_CAPABILITY_IDS = new Set<CapabilityId>([
  'file_viewer',
  'editor',
  'terminal',
  'goal_execution',
  'cto_orchestration',
  'infrastructure',
])

const repositoryWire = z
  .object({
    name: z.string().min(1).max(160).optional(),
    rootDisplay: z.string().min(1).max(160).optional(),
    branch: z.string().min(1).max(256).optional(),
    revision: z.string().min(1).max(160).optional(),
    commit: z.string().min(1).max(160).optional(),
    headCommit: z.string().min(1).max(160).optional(),
    headTree: z.string().min(1).max(160).optional(),
    clean: z.boolean().optional(),
    dirty: z.boolean().optional(),
    dirtyDigest: z.string().min(8).max(160).optional(),
    remote: z.string().max(2_048).nullable().optional(),
    // Accepted for compatibility only; local paths never become display data.
    path: z.string().optional(),
  })
  .strict()

export function mapRepository(payload: unknown): ApplicationInstance['repository'] {
  if (payload === undefined || payload === null) return undefined
  const wire = repositoryWire.parse(payload)
  const name = wire.name ?? wire.rootDisplay
  if (!name) {
    failClosed('repository projection supplies no path-free display identity')
  }
  if (
    name.includes('/') ||
    name.includes('\\') ||
    name.includes('@') ||
    name.includes(':') ||
    [...name].some((character) => {
      const code = character.charCodeAt(0)
      return code <= 0x1f || code === 0x7f
    })
  ) {
    failClosed('repository projection carries an unsafe display identity')
  }
  return {
    name,
    branch: wire.branch ?? 'main',
    revision: wire.revision ?? wire.commit ?? wire.headCommit ?? '',
    clean: wire.clean ?? (wire.dirty !== undefined ? !wire.dirty : true),
  }
}

const provenanceIdentifierWire = z
  .string()
  .min(1)
  .max(160)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/)

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const code = character.charCodeAt(0)
    return code <= 0x1f || code === 0x7f
  })
}

const sourceVersionWire = z
  .string()
  .min(1)
  .max(128)
  .refine((value) => !containsControlCharacter(value), {
    message: 'source version contains a control character',
  })

/**
 * Deliberately reviewed allowlist for the `PersistentApp.inspect().source`
 * projection. Sensitive/local fields such as `checkoutLocation` and `profile`
 * are not accepted, and unknown keys do not pass through to browser state.
 *
 * Some fields are accepted only so older external-repository observations can
 * be parsed safely; they are intentionally not copied into the domain model.
 */
const applicationSourceWire = z
  .object({
    formatVersion: z.string().nullish(),
    kind: z.string().nullish(),
    templateId: provenanceIdentifierWire.nullish(),
    repository: z.string().min(1).max(512).nullish(),
    requestedRef: z.string().min(1).max(256).nullish(),
    resolvedCommit: z.string().min(1).max(160).nullish(),
    resolvedTree: z.string().min(1).max(160).nullish(),
    manifestPath: z.string().min(1).max(512).nullish(),
    manifestDigest: z.string().min(1).max(128).nullish(),
    sourceDigest: z.string().min(1).max(128).nullish(),
    sourceClass: provenanceIdentifierWire.nullish(),
    productionEligible: z.boolean().nullish(),
    sourceAccessClass: z.enum(['canonical_release', 'development_candidate']).nullish(),
    productionInstallAllowed: z.boolean().nullish(),
    sourceKind: provenanceIdentifierWire.nullish(),
    ownership: provenanceIdentifierWire.nullish(),
    version: sourceVersionWire.nullish(),
    // Existing user-owned repository observation fields.
    source: z.string().min(1).max(512).nullish(),
    remote: z.string().min(1).max(512).nullish(),
    headCommit: z.string().min(1).max(160).nullish(),
    headTree: z.string().min(1).max(160).nullish(),
    branch: z.string().min(1).max(256).nullish(),
    dirty: z.boolean().nullish(),
    submodulesDeclared: z.boolean().nullish(),
    lfsPointersDetected: z.boolean().nullish(),
    fileCount: z.number().int().nonnegative().nullish(),
    estimatedBytes: z.number().int().nonnegative().nullish(),
    url: z.string().min(1).max(512).nullish(),
  })
  .strict()

const ownershipCountsWire = z
  .object({
    template: z.number().int().nonnegative().max(1_000_000),
    instance: z.number().int().nonnegative().max(1_000_000),
    generated: z.number().int().nonnegative().max(1_000_000),
    override: z.number().int().nonnegative().max(1_000_000),
  })
  .strict()

const ownershipPathsWire = z
  .object({
    template: z.array(z.string().min(1).max(512)).max(24),
    instance: z.array(z.string().min(1).max(512)).max(24),
    generated: z.array(z.string().min(1).max(512)).max(24),
    override: z.array(z.string().min(1).max(512)).max(24),
  })
  .strict()

const ownershipTruncatedWire = z
  .object({
    template: z.boolean(),
    instance: z.boolean(),
    generated: z.boolean(),
    override: z.boolean(),
  })
  .strict()

const applicationOwnershipWire = z
  .object({
    counts: ownershipCountsWire,
    paths: ownershipPathsWire,
    truncated: ownershipTruncatedWire,
  })
  .strict()

const FULL_GIT_OID = /^[0-9a-f]{40}$/
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/
const COMPATIBILITY_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/
const OWNERSHIP_CATEGORIES = ['template', 'instance', 'generated', 'override'] as const

function safeSourceRepository(value: string): string {
  if (/%(?:2e|2f|5c)/i.test(value)) {
    failClosed('application source repository contains encoded path syntax')
  }
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    failClosed('application source repository is not a public HTTPS identity')
  }
  if (
    parsed.protocol !== 'https:' ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    failClosed('application source repository is not a credential-free HTTPS identity')
  }
  if (
    value.includes('\\') ||
    value.split('/').some((segment) => segment === '.' || segment === '..') ||
    parsed.pathname.split('/').some((segment) => segment === '.' || segment === '..')
  ) {
    failClosed('application source repository contains unsafe path syntax')
  }
  return value
}

function safeOwnershipPath(value: string): string {
  if (
    value.startsWith('/') ||
    value.startsWith('\\') ||
    /^[A-Za-z]:/.test(value) ||
    value.includes('\\') ||
    containsControlCharacter(value) ||
    value.includes('://')
  ) {
    failClosed('application ownership projection contains a local or unsafe path')
  }
  const segments = value.split('/')
  if (segments.some((segment) => !segment || segment === '.' || segment === '..')) {
    failClosed('application ownership projection contains path traversal')
  }
  return value
}

function mapOwnership(
  payload: z.infer<typeof applicationOwnershipWire> | undefined,
): ApplicationProvenance['ownership'] {
  if (!payload) return undefined

  const seen = new Set<string>()
  for (const category of OWNERSHIP_CATEGORIES) {
    const paths = payload.paths[category]
    const count = payload.counts[category]
    const truncated = payload.truncated[category]
    if (
      count < paths.length ||
      (truncated && count <= paths.length) ||
      (!truncated && count !== paths.length)
    ) {
      failClosed(`application ownership count for "${category}" is inconsistent`)
    }
    for (const path of paths) {
      const safe = safeOwnershipPath(path)
      if (seen.has(safe)) {
        failClosed(`application ownership path "${safe}" has more than one authority`)
      }
      seen.add(safe)
    }
  }

  return {
    counts: { ...payload.counts },
    paths: {
      template: payload.paths.template.map(safeOwnershipPath),
      instance: payload.paths.instance.map(safeOwnershipPath),
      generated: payload.paths.generated.map(safeOwnershipPath),
      override: payload.paths.override.map(safeOwnershipPath),
    },
    truncated: { ...payload.truncated },
  }
}

function mapApplicationProvenance(
  sourcePayload: z.infer<typeof applicationSourceWire> | undefined,
  versionPayload: string | null | undefined,
  ownershipPayload: z.infer<typeof applicationOwnershipWire> | undefined,
): ApplicationProvenance | undefined {
  if (!sourcePayload) {
    if (ownershipPayload) failClosed('application ownership was projected without source identity')
    return undefined
  }

  const resolvedCommit = sourcePayload.resolvedCommit ?? sourcePayload.headCommit ?? undefined
  const resolvedTree = sourcePayload.resolvedTree ?? sourcePayload.headTree ?? undefined
  if (
    sourcePayload.resolvedCommit &&
    sourcePayload.headCommit &&
    sourcePayload.resolvedCommit !== sourcePayload.headCommit
  ) {
    failClosed('application source carries contradictory commit identities')
  }
  if (
    sourcePayload.resolvedTree &&
    sourcePayload.headTree &&
    sourcePayload.resolvedTree !== sourcePayload.headTree
  ) {
    failClosed('application source carries contradictory tree identities')
  }

  const compatibilitySource =
    resolvedCommit?.startsWith('fixture:') === true ||
    sourcePayload.sourceClass === 'synthetic_fixture' ||
    sourcePayload.sourceClass === 'compatibility_fixture' ||
    sourcePayload.sourceClass === 'compatibility_snapshot' ||
    sourcePayload.sourceKind === 'bundled_public_fixture'

  let exactCommit: string | undefined
  let exactTree: string | undefined
  let compatibilityRevision: string | undefined
  let compatibilityTree: string | undefined
  if (resolvedCommit) {
    if (FULL_GIT_OID.test(resolvedCommit)) {
      exactCommit = resolvedCommit
    } else if (compatibilitySource && COMPATIBILITY_REFERENCE.test(resolvedCommit)) {
      compatibilityRevision = resolvedCommit
    } else {
      failClosed('application source commit is not an exact Git object identity')
    }
  }
  if (resolvedTree) {
    if (FULL_GIT_OID.test(resolvedTree) && !compatibilityRevision) {
      exactTree = resolvedTree
    } else if (
      compatibilityRevision &&
      COMPATIBILITY_REFERENCE.test(resolvedTree)
    ) {
      compatibilityTree = resolvedTree
    } else {
      failClosed('application source tree is not consistent with its source identity')
    }
  }

  const manifestDigest = sourcePayload.manifestDigest ?? undefined
  const sourceDigest = sourcePayload.sourceDigest ?? undefined
  if (manifestDigest && !SHA256_DIGEST.test(manifestDigest)) {
    failClosed('application source manifest digest is malformed')
  }
  if (sourceDigest && !SHA256_DIGEST.test(sourceDigest)) {
    failClosed('application source digest is malformed')
  }

  const authorityClass = sourcePayload.sourceClass
  if (
    (authorityClass === 'canonical_source' ||
      authorityClass === 'canonical_release' ||
      authorityClass === 'development_candidate') &&
    (!exactCommit || !exactTree || !manifestDigest)
  ) {
    failClosed(`application ${authorityClass} source lacks complete immutable identity`)
  }
  const hasSourceAccessClass = sourcePayload.sourceAccessClass != null
  const hasProductionInstallAllowed = sourcePayload.productionInstallAllowed != null
  if (hasSourceAccessClass !== hasProductionInstallAllowed) {
    failClosed('application source access evidence must include both class and install authority')
  }
  if (
    sourcePayload.sourceAccessClass != null &&
    !(
      (sourcePayload.sourceAccessClass === 'canonical_release' &&
        sourcePayload.productionInstallAllowed === true) ||
      (sourcePayload.sourceAccessClass === 'development_candidate' &&
        sourcePayload.productionInstallAllowed === false)
    )
  ) {
    failClosed('application source access evidence is contradictory')
  }

  const sourceVersion = sourcePayload.version ?? undefined
  const projectedVersion = versionPayload ?? undefined
  const version = sourceVersion ?? projectedVersion
  if (
    sourceVersion !== undefined &&
    projectedVersion !== undefined &&
    sourceVersion !== projectedVersion
  ) {
    failClosed('application source carries contradictory version identities')
  }

  const source: ApplicationProvenance['source'] = {
    templateId: sourcePayload.templateId ?? undefined,
    repository: sourcePayload.repository
      ? safeSourceRepository(sourcePayload.repository)
      : undefined,
    resolvedCommit: exactCommit,
    resolvedTree: exactTree,
    manifestDigest,
    sourceDigest,
    sourceKind: sourcePayload.sourceKind ?? undefined,
    sourceClass: sourcePayload.sourceClass ?? undefined,
    sourceAccessClass: sourcePayload.sourceAccessClass ?? undefined,
    ownership: sourcePayload.ownership ?? undefined,
    version,
    productionEligible: sourcePayload.productionEligible ?? undefined,
    productionInstallAllowed: sourcePayload.productionInstallAllowed ?? undefined,
    compatibilityRevision,
    compatibilityTree,
  }
  if (Object.values(source).every((value) => value === undefined)) {
    failClosed('application source projection contains no browser-safe identity')
  }

  return {
    source,
    ownership: mapOwnership(ownershipPayload),
  }
}

const recoveryWire = z.object({
  status: z.string().optional(),
  latest: z.object({
    createdAt: isoTimestamp.optional(),
    receiptId: z.string().optional(),
    backupReceipt: z.object({
      receiptId: z.string(),
    }).optional(),
  }).nullable().optional(),
  state: z.string().optional(),
  lastBackupAt: isoTimestamp.optional(),
  nextDueAt: isoTimestamp.optional(),
  lastReceiptId: z.string().optional(),
  detail: z.string().optional(),
  operatorInspectionRequired: z.boolean().optional(),
  verificationIssues: z.array(z.string()).optional(),
})

const packageStateWire = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('study-state'),
    goal: z.string(),
    goalProgressPercent: z.number().min(0).max(100),
    activities: z.array(z.object({
      id: z.string(),
      title: z.string(),
      reason: z.string().optional(),
      state: z.enum(['not_started', 'in_progress', 'paused', 'done']),
      updatedAt: isoTimestamp,
    })),
    evidence: z.array(z.object({
      id: z.string(),
      title: z.string(),
      state: z.enum(['missing', 'draft', 'self_reported', 'verified']),
      updatedAt: isoTimestamp,
    })),
    planDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/).optional(),
    canUndo: z.boolean().optional(),
    lastTransition: z.record(z.string(), z.unknown()).optional(),
  }),
  z.object({
    kind: z.literal('checklist-state'),
    items: z.array(z.object({
      id: z.string(),
      title: z.string(),
      done: z.boolean(),
      updatedAt: isoTimestamp,
    })),
  }),
])

const instanceWire = z.object({
  id: z.string().optional(),
  instanceId: z.string().optional(),
  name: z.string().optional(),
  applicationId: z.string().optional(),
  packageId: z.string().optional(),
  applicationName: z.string().optional(),
  applicationDisplayName: z.string().optional(),
  health: z.string().optional(),
  conversationId: z.string().optional(),
  capabilities: z.unknown().optional(),
  attention: z.array(z.unknown()).optional(),
  recentActivity: z.array(z.unknown()).optional(),
  activity: z.array(z.unknown()).optional(),
  receiptIds: z.array(z.string()).optional(),
  recovery: recoveryWire.optional(),
  packageState: packageStateWire.optional(),
  instance: z.object({
    id: z.string(),
    name: z.string().optional(),
    pathState: z.string().optional(),
  }).optional(),
  repository: repositoryWire.optional(),
  source: applicationSourceWire.optional(),
  version: sourceVersionWire.nullish(),
  ownership: applicationOwnershipWire.optional(),
  runtimeIdentity: z.string().optional(),
  pinned: z.boolean().optional(),
  createdAt: isoTimestamp.optional(),
  created: isoTimestamp.optional(),
  lastOpenedAt: isoTimestamp.optional(),
})

export interface InstanceView {
  instance: ApplicationInstance
}

export function mapInstance(
  payload: unknown,
  context?: {
    experience?: ExperienceView
    experienceResolution?: ApplicationInstance['experienceResolution']
    index?: Record<string, unknown>
    pinned?: boolean
    lastOpenedAt?: string
  },
): ApplicationInstance {
  const wire = instanceWire.parse(payload)
  const id = wire.id ?? wire.instanceId ?? wire.instance?.id ??
    (typeof context?.index?.instanceId === 'string' ? context.index.instanceId : undefined)
  if (!id) failClosed('instance projection without identity')
  const packageId = wire.applicationId ?? wire.packageId ?? context?.experience?.packageId ??
    (typeof context?.index?.applicationId === 'string' ? context.index.applicationId : undefined)
  if (!packageId) failClosed(`instance ${id} has no application identity`)
  const indexPathState =
    typeof context?.index?.pathState === 'string' ? context.index.pathState : undefined
  const healthRaw = wire.health ?? (wire.instance?.pathState === 'stale' || indexPathState === 'stale' ? 'unavailable' : 'unknown')
  const health = HEALTH_MAP[healthRaw]
  if (!health) failClosed(`instance ${id} reported unknown health "${healthRaw}"`)
  const pathUnavailable = wire.instance?.pathState === 'stale' || indexPathState === 'stale'
  const capabilities = (context?.experience?.capabilities ?? mapCapabilities(wire.capabilities)).map(
    (capability): CapabilityState =>
      pathUnavailable &&
      PATH_BOUND_CAPABILITY_IDS.has(capability.id) &&
      (capability.status === 'available' || capability.status === 'degraded')
        ? {
            ...capability,
            status: 'environment_gated',
            reason: 'The cataloged application path is unavailable. Restore or refresh the application path to use this capability.',
          }
        : capability,
  )
  const recovery = wire.recovery
  const recoveryState = recovery?.state ?? recovery?.status
  return {
    id,
    name: wire.name ?? wire.instance?.name ??
      (typeof context?.index?.name === 'string' ? context.index.name : id),
    packageId,
    packageName: wire.applicationName ?? packageId,
    packageDisplayName: wire.applicationDisplayName ?? wire.applicationName ?? packageId,
    health,
    attention: (wire.attention ?? []).map((a) => mapAttentionItem(a, id)),
    recentActivity: (wire.recentActivity ?? wire.activity ?? []).map((a) => mapActivityItem(a, id)),
    settings: defaultAppSettings(id),
    conversationId: wire.conversationId,
    capabilities,
    experience: context?.experience?.experience,
    experienceResolution: context?.experienceResolution,
    receiptIds: wire.receiptIds ?? [],
    recovery: recovery
      ? {
          state:
            recoveryState === 'no_backup'
              ? 'due'
              : recoveryState === 'verified'
                ? 'current'
                : recoveryState === 'degraded'
                  ? 'failed'
                  : (['current', 'due', 'running', 'failed', 'not_configured'] as const).find((s) => s === recoveryState) ?? 'not_configured',
          lastBackupAt: recovery.lastBackupAt ?? recovery.latest?.createdAt,
          nextDueAt: recovery.nextDueAt,
          lastReceiptId:
            recovery.lastReceiptId ??
            recovery.latest?.receiptId ??
            recovery.latest?.backupReceipt?.receiptId,
          detail:
            recovery.detail ??
            (recoveryState === 'no_backup'
              ? 'No verified backup has been recorded.'
              : recoveryState === 'degraded'
                ? recovery.verificationIssues?.join(' ') ||
                  'Backup verification requires operator inspection.'
                : undefined),
        }
      : { state: 'not_configured' },
    packageState: wire.packageState,
    repository: mapRepository(wire.repository),
    provenance: mapApplicationProvenance(wire.source, wire.version, wire.ownership),
    runtimeIdentity: wire.runtimeIdentity,
    pinned: context?.pinned ?? wire.pinned ?? false,
    createdAt: wire.createdAt ?? wire.created ??
      (typeof context?.index?.createdAt === 'string' ? context.index.createdAt : new Date().toISOString()),
    lastOpenedAt: context?.lastOpenedAt ?? wire.lastOpenedAt,
  }
}

export function mapInstanceIndex(payload: unknown): unknown[] {
  return indexPayload(payload, ['instances', 'items'])
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings projections (revision-carrying)
// ─────────────────────────────────────────────────────────────────────────────

const settingsScalarWire = z.union([z.string(), z.number(), z.boolean()])
const boundedSettingsValuesWire = z
  .record(z.string(), settingsScalarWire)
  .refine((values) => Object.keys(values).length >= 1 && Object.keys(values).length <= 16, {
    message: 'settings receipt values must contain one to sixteen fields',
  })

const settingsMutationReceiptWire = z
  .object({
    formatVersion: z.literal('stateport.settings-mutation-receipt/v1'),
    receiptId: z.string().regex(/^[a-f0-9]{24}$/),
    scope: z.enum(['global', 'application']),
    instanceId: z.string().nullable(),
    action: z.enum(['settings.patch', 'settings.rollback']),
    status: z.literal('applied'),
    revision: z.number().int().positive(),
    changes: boundedSettingsValuesWire,
    previousValues: boundedSettingsValuesWire,
    effectivePolicy: z.string().min(1).max(512),
    createdAt: z.iso.datetime(),
  })
  .strict()
  .refine(
    (receipt) => {
      const changed = Object.keys(receipt.changes).sort()
      const previous = Object.keys(receipt.previousValues).sort()
      return changed.length === previous.length &&
        changed.every((key, index) => key === previous[index])
    },
    { message: 'settings receipt changes and previous values must cover the same fields' },
  )

const settingsProjectionWire = z.object({
  formatVersion: z.literal('stateport.settings-projection/v1'),
  scope: z.enum(['global', 'application']),
  instanceId: z.string().nullable(),
  revision: z.number().int().nonnegative(),
  settings: z.record(z.string(), z.unknown()).optional(),
  values: z.record(z.string(), z.unknown()).optional(),
  receiptId: z.string().optional(),
  sections: z.array(z.object({
    fields: z.array(z.object({
      key: z.string(),
      value: z.unknown().optional(),
      effectiveValue: z.unknown().optional(),
      editable: z.boolean().optional(),
    })),
  })),
  recentReceipts: z.array(settingsMutationReceiptWire).max(10),
})

export interface SettingsProjection<T> {
  revision: number
  settings: T
  receiptId?: string
  rollbackTargets: GlobalSettingsRollbackTarget[]
}

function deepMergeRecord(base: Record<string, unknown>, patch: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...base }
  for (const [key, value] of Object.entries(patch)) {
    const current = out[key]
    out[key] =
      isRecord(current) && isRecord(value) ? deepMergeRecord(current, value) : value
  }
  return out
}

function parseSettingsResponse(
  payload: unknown,
  expectedScope: 'global' | 'application',
  expectedInstanceId: string | null,
  expectedAction?: 'settings.patch' | 'settings.rollback',
) {
  const nested = isRecord(payload) && payload.projection !== undefined
  const parsedProjection = settingsProjectionWire.safeParse(
    nested ? payload.projection : payload,
  )
  if (!parsedProjection.success) {
    failClosed('settings projection does not match the current typed contract')
  }
  const wire = parsedProjection.data
  if (
    wire.scope !== expectedScope ||
    wire.instanceId !== expectedInstanceId
  ) {
    failClosed('settings projection carries a mismatched scope or instance identity')
  }
  let receiptId: string | undefined
  if (nested) {
    const parsedReceipt = settingsMutationReceiptWire.safeParse(payload.receipt)
    if (!parsedReceipt.success) {
      failClosed('settings mutation receipt does not match the current typed contract')
    }
    const receipt = parsedReceipt.data
    if (
      receipt.scope !== expectedScope ||
      receipt.instanceId !== expectedInstanceId ||
      receipt.revision !== wire.revision ||
      (expectedAction !== undefined && receipt.action !== expectedAction) ||
      wire.recentReceipts[0]?.receiptId !== receipt.receiptId
    ) {
      failClosed('settings mutation receipt does not match its projection')
    }
    receiptId = receipt.receiptId
  }
  const receiptIds = new Set<string>()
  const receiptRevisions = new Set<number>()
  for (const receipt of wire.recentReceipts) {
    if (
      receipt.scope !== expectedScope ||
      receipt.instanceId !== expectedInstanceId ||
      receipt.revision > wire.revision ||
      receiptIds.has(receipt.receiptId) ||
      receiptRevisions.has(receipt.revision)
    ) {
      failClosed('settings history carries a mismatched or duplicate identity')
    }
    receiptIds.add(receipt.receiptId)
    receiptRevisions.add(receipt.revision)
  }
  return { wire, receiptId }
}

function settingsRollbackTargets(
  wire: z.infer<typeof settingsProjectionWire>,
): GlobalSettingsRollbackTarget[] {
  return wire.recentReceipts.map((receipt) => ({
    receiptId: receipt.receiptId,
    revision: receipt.revision,
    action: receipt.action,
    createdAt: receipt.createdAt,
    changes: receipt.changes,
    previousValues: receipt.previousValues,
  }))
}

/** Flatten the backend's typed settings sections into their exact keys. */
function settingsFieldValues(
  wire: z.infer<typeof settingsProjectionWire>,
): Record<string, unknown> {
  return Object.fromEntries(
    wire.sections.flatMap((section) =>
      section.fields.map((field) => [
        field.key,
        field.effectiveValue !== undefined ? field.effectiveValue : field.value,
      ]),
    ),
  )
}

/**
 * Global settings: the backend stores the *service-owned* keys; the frontend
 * owns defaults for UI-only groups. The projection is merged over the shared
 * defaults (the same constants the mock starts from — defaults, not mock
 * data) and then validated against the full settings schema.
 */
export function mapGlobalSettings(
  payload: unknown,
  validate: (candidate: unknown) => GlobalSettings,
  expectedAction?: 'settings.patch' | 'settings.rollback',
): SettingsProjection<GlobalSettings> {
  const { wire, receiptId } = parseSettingsResponse(
    payload,
    'global',
    null,
    expectedAction,
  )
  const fields = settingsFieldValues(wire)
  const defaults = defaultGlobalSettings()
  defaults.advanced.adapterMode = 'http'
  defaults.advanced.localServiceEndpoint =
    typeof window === 'undefined' ? 'same-origin' : window.location.origin
  if (typeof fields['general.appearance'] === 'string') {
    const appearance = fields['general.appearance']
    if (appearance === 'system' || appearance === 'light' || appearance === 'dark') {
      defaults.appearance.theme = appearance
    }
  }
  if (typeof fields['general.defaultLandingView'] === 'string') {
    defaults.general.defaultLandingPage =
      fields['general.defaultLandingView'] === 'last_workspace' ? 'last_workspace' : 'applications'
  }
  if (typeof fields['notifications.level'] === 'string') {
    const level = fields['notifications.level']
    defaults.notifications.level =
      level === 'important' ? 'important_only' : level === 'none' ? 'none' : 'all'
  }
  const merged = deepMergeRecord(
    defaults as unknown as Record<string, unknown>,
    (wire.settings ?? wire.values ?? {}) as Record<string, unknown>,
  )
  return {
    revision: wire.revision,
    settings: validate(merged),
    receiptId: receiptId ?? wire.receiptId,
    rollbackTargets: settingsRollbackTargets(wire),
  }
}

export function mapAppSettings(
  payload: unknown,
  instanceId: string,
  validate: (candidate: unknown) => AppSettings,
  expectedAction?: 'settings.patch' | 'settings.rollback',
): SettingsProjection<AppSettings> {
  const { wire, receiptId } = parseSettingsResponse(
    payload,
    'application',
    instanceId,
    expectedAction,
  )
  const merged = deepMergeRecord(
    defaultAppSettings(instanceId) as unknown as Record<string, unknown>,
    (wire.settings ?? wire.values ?? {}) as Record<string, unknown>,
  )
  merged.instanceId = instanceId
  return {
    revision: wire.revision,
    settings: validate(merged),
    receiptId: receiptId ?? wire.receiptId,
    rollbackTargets: settingsRollbackTargets(wire),
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Activity / attention (stateport.activity-receipts-projection/v1)
// ─────────────────────────────────────────────────────────────────────────────

const activityItemWire = z.object({
  id: z.string().optional(),
  action: z.string().optional(),
  operation: z.string().optional(),
  status: z.string().optional(),
  occurredAt: isoTimestamp.optional(),
  instanceId: z.string().optional(),
  kind: z.string().optional(),
  title: z.string().optional(),
  detail: z.string().optional(),
  createdAt: isoTimestamp.optional(),
  at: isoTimestamp.optional(),
  read: z.boolean().optional(),
  receiptId: z.string().optional(),
  relatedReceiptId: z.string().optional(),
  route: z.string().optional(),
})

export function mapActivityItem(payload: unknown, fallbackInstanceId?: string): ActivityItem {
  const wire = activityItemWire.parse(payload)
  const createdAt = wire.createdAt ?? wire.at ?? wire.occurredAt ?? new Date().toISOString()
  const instanceId = bindInstanceIdentity(
    wire.instanceId,
    fallbackInstanceId,
    'activity item',
  )
  const id =
    wire.id ??
    wire.receiptId ??
    `activity:${fallbackInstanceId ?? 'unknown'}:${encodeURIComponent(wire.action ?? wire.kind ?? 'event')}:${createdAt}`
  return {
    id,
    instanceId,
    kind: wire.kind ?? 'activity',
    // Surfaces never render a raw machine action like `governed_run.apply`:
    // without an explicit title the identifier goes through the same
    // humanizer the receipt list uses.
    title: wire.title ?? (wire.action ? humanReceiptAction(wire.action) : undefined) ?? wire.kind ?? 'Activity',
    detail: wire.detail ?? wire.status,
    createdAt,
    // Recent receipt activity has no unread lifecycle; only attention items
    // may be transitioned through the backend.
    read: wire.read ?? wire.occurredAt !== undefined,
    relatedReceiptId: wire.relatedReceiptId ?? wire.receiptId,
    route: wire.route,
  }
}

const attentionWire = z.object({
  id: z.string().optional(),
  attentionId: z.string().optional(),
  instanceId: z.string().optional(),
  title: z.string().optional(),
  detail: z.string().optional(),
  severity: z.string().optional(),
  createdAt: isoTimestamp.optional(),
  at: isoTimestamp.optional(),
  firstObservedAt: isoTimestamp.optional(),
  lastObservedAt: isoTimestamp.optional(),
  readAt: isoTimestamp.nullable().optional(),
  acknowledgedAt: isoTimestamp.nullable().optional(),
  sourceKind: z.string().optional(),
  state: z.string().optional(),
  version: z.number().int().nonnegative().optional(),
  acknowledged: z.boolean().optional(),
  route: z.string().optional(),
  actionRoute: z.string().optional(),
})

const SEVERITY_MAP: Record<string, AttentionItem['severity']> = {
  info: 'info',
  notice: 'info',
  action_needed: 'action_needed',
  warning: 'action_needed',
  urgent: 'urgent',
  critical: 'urgent',
}

export function mapAttentionItem(payload: unknown, fallbackInstanceId?: string): AttentionItem {
  const wire = attentionWire.parse(payload)
  const id = wire.id ?? wire.attentionId
  if (!id) failClosed('attention item without identity')
  const instanceId = bindInstanceIdentity(
    wire.instanceId,
    fallbackInstanceId,
    `attention item ${id}`,
  )
  if (!instanceId) failClosed('attention item without instance identity')
  return {
    id,
    instanceId,
    title: wire.title ?? 'Attention needed',
    detail: wire.detail ?? '',
    // Unknown severities surface as action_needed (visible), never hidden.
    severity:
      SEVERITY_MAP[
        wire.severity ??
          (wire.sourceKind === 'application_health' || wire.state === 'open' ? 'action_needed' : 'info')
      ] ?? 'action_needed',
    createdAt: wire.createdAt ?? wire.at ?? wire.firstObservedAt ?? wire.lastObservedAt ?? new Date().toISOString(),
    read:
      (wire.readAt !== null && wire.readAt !== undefined) ||
      wire.acknowledged === true ||
      (wire.acknowledgedAt !== null && wire.acknowledgedAt !== undefined),
    acknowledged:
      wire.acknowledged ?? (wire.acknowledgedAt !== null && wire.acknowledgedAt !== undefined),
    actionRoute: wire.actionRoute ?? wire.route,
  }
}

export interface ActivityProjectionView {
  version: number
  attentionVersions: Record<string, number>
  activity: ActivityItem[]
  attention: AttentionItem[]
  receipts: Receipt[]
}

const activityProjectionWire = z.object({
  formatVersion: z.string().optional(),
  instanceId: z.string().optional(),
  version: z.number().int().nonnegative().optional(),
  activity: z.array(z.unknown()).optional(),
  items: z.array(z.unknown()).optional(),
  recentActivity: z.array(z.unknown()).optional(),
  attention: z.array(z.unknown()).optional(),
  receipts: z.array(z.unknown()).optional(),
})

export function mapActivityProjection(payload: unknown, instanceId: string): ActivityProjectionView {
  const wire = activityProjectionWire.parse(payload)
  if (wire.formatVersion !== undefined && wire.formatVersion !== FORMAT.activityReceiptsProjection) {
    failClosed(`activity projection formatVersion "${wire.formatVersion}"`, `expected ${FORMAT.activityReceiptsProjection}`)
  }
  bindInstanceIdentity(wire.instanceId, instanceId, 'activity projection')
  const attention = (wire.attention ?? []).map((a) => mapAttentionItem(a, instanceId))
  const attentionVersions = Object.fromEntries(
    (wire.attention ?? []).flatMap((entry) => {
      const parsed = attentionWire.parse(entry)
      const id = parsed.id ?? parsed.attentionId
      return id && parsed.version !== undefined ? [[id, parsed.version] as const] : []
    }),
  )
  return {
    version: wire.version ?? Math.max(0, ...Object.values(attentionVersions)),
    attentionVersions,
    activity: (wire.activity ?? wire.items ?? wire.recentActivity ?? []).map((a) => mapActivityItem(a, instanceId)),
    attention,
    receipts: (wire.receipts ?? []).map((r) => mapReceipt(r, instanceId)),
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Approvals index
// ─────────────────────────────────────────────────────────────────────────────

const approvalWire = z.object({
  id: z.string(),
  instanceId: z.string().optional(),
  kind: z.string().optional(),
  title: z.string().optional(),
  operationType: z.string().optional(),
  risk: z.string().optional(),
  status: z.string().optional(),
  scope: z.array(z.string()).optional(),
  beforeSummary: z.string().optional(),
  afterSummary: z.string().optional(),
  planDigest: digestWire.optional(),
  digest: digestWire.optional(),
  planId: z.string().optional(),
  targetId: z.string().optional(),
  runId: z.string().optional(),
  whyRequired: z.string().optional(),
  requestedAt: isoTimestamp.optional(),
  createdAt: isoTimestamp.optional(),
  expiresAt: isoTimestamp.optional(),
  currentDigest: digestWire.optional(),
  decidedAt: isoTimestamp.optional(),
  decisionReason: z.string().optional(),
  resultingReceiptId: z.string().optional(),
  receiptId: z.string().optional(),
  relatedConversationId: z.string().optional(),
  decision: z.object({
    kind: z.enum(['run_approval', 'run_proposal', 'infrastructure_plan', 'authorization_grant', 'goal_execution', 'template_upgrade']),
    expectedInstanceId: z.string(),
    expectedRevision: z.number().int().nonnegative().optional(),
    expectedDigest: z.string().min(8),
  }),
})

const APPROVAL_KIND_MAP: Record<string, Approval['kind']> = {
  infrastructure_plan: 'infrastructure_plan',
  infrastructure: 'infrastructure_plan',
  orchestration_run: 'orchestration_run',
  run: 'orchestration_run',
  authorization_grant: 'authorization_grant',
  grant: 'authorization_grant',
  goal_execution: 'goal_execution',
  template_upgrade: 'template_upgrade',
  file_write: 'file_write',
  capability_change: 'capability_change',
}

const APPROVAL_STATUS_MAP: Record<string, Approval['status']> = {
  pending: 'pending',
  approved: 'approved',
  rejected: 'rejected',
  expired: 'expired',
}

export function mapApproval(payload: unknown): Approval {
  const wire = approvalWire.parse(payload)
  const kind = APPROVAL_KIND_MAP[wire.kind ?? '']
  if (!kind) failClosed(`approval ${wire.id} has unknown kind "${wire.kind ?? ''}"`)
  if (!wire.instanceId) failClosed(`approval ${wire.id} has no instance identity`)
  if (wire.decision.expectedInstanceId !== wire.instanceId) {
    failClosed(`approval ${wire.id} decision instance identity does not match its indexed instance`)
  }
  const status = APPROVAL_STATUS_MAP[wire.status ?? 'pending']
  if (!status) failClosed(`approval ${wire.id} has unknown status "${wire.status ?? ''}"`)
  const planDigest = wire.planDigest ?? wire.digest
  if (!planDigest) failClosed(`approval ${wire.id} carries no exact decision digest`)
  if (wire.decision.expectedDigest !== planDigest.value) {
    failClosed(`approval ${wire.id} decision digest does not match its indexed digest`)
  }
  const runDecision = wire.decision.kind === 'run_approval' || wire.decision.kind === 'run_proposal'
  const revisionDecision = runDecision || wire.decision.kind === 'goal_execution'
  if (revisionDecision && wire.decision.expectedRevision === undefined) {
    failClosed(`approval ${wire.id} carries no exact decision revision`)
  }
  if (runDecision && (kind !== 'orchestration_run' || !wire.runId)) {
    failClosed(`approval ${wire.id} run decision has no governed run identity`)
  }
  if (
    (wire.decision.kind === 'infrastructure_plan' && kind !== 'infrastructure_plan') ||
    (wire.decision.kind === 'authorization_grant' && kind !== 'authorization_grant') ||
    (wire.decision.kind === 'goal_execution' && kind !== 'goal_execution') ||
    ((wire.decision.kind === 'template_upgrade') !== (kind === 'template_upgrade'))
  ) {
    failClosed(`approval ${wire.id} decision kind does not match its indexed kind`)
  }
  const risk = wire.risk === 'medium' || wire.risk === 'high' ? wire.risk : 'low'
  const requestedAt = wire.requestedAt ?? wire.createdAt
  if (!requestedAt) failClosed(`approval ${wire.id} carries no authoritative request time`)
  if (wire.decision.kind === 'template_upgrade' && !wire.targetId) {
    failClosed(`approval ${wire.id} template upgrade has no operation identity`)
  }
  return {
    id: wire.id,
    instanceId: wire.instanceId,
    kind,
    title: wire.title ?? 'Approval requested',
    operationType: wire.operationType ?? kind,
    risk,
    status,
    scope: wire.scope ?? [],
    beforeSummary: wire.beforeSummary ?? '',
    afterSummary: wire.afterSummary ?? '',
    planDigest,
    planId: wire.planId,
    targetId: wire.targetId,
    runId: wire.runId,
    whyRequired: wire.whyRequired ?? 'This operation changes managed state and requires an explicit decision.',
    requestedAt,
    expiresAt: wire.expiresAt,
    decision: wire.decision,
    currentDigest: wire.currentDigest,
    decidedAt: wire.decidedAt,
    decisionReason: wire.decisionReason,
    resultingReceiptId: wire.resultingReceiptId ?? wire.receiptId,
    relatedConversationId: wire.relatedConversationId,
  } as Approval
}

export function mapApprovalIndex(payload: unknown): Approval[] {
  return indexPayload(payload, ['approvals', 'items']).map(mapApproval)
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipts (stateport.activity-receipts-projection/v1 receipt entries)
// ─────────────────────────────────────────────────────────────────────────────

const RECEIPT_RESULT_MAP: Record<string, ReceiptResult> = {
  approved: 'approved',
  applied: 'applied',
  executed: 'executed',
  completed: 'completed',
  validated: 'validated',
  verified: 'validated',
  completed_without_change: 'completed_without_change',
  rejected: 'rejected',
  cancelled: 'cancelled',
  canceled: 'cancelled',
  failed: 'failed',
  error: 'failed',
  human_accepted: 'human_accepted',
}

const receiptWire = z.object({
  id: z.string().optional(),
  receiptId: z.string().optional(),
  instanceId: z.string().optional(),
  packageId: z.string().optional(),
  applicationId: z.string().optional(),
  actionName: z.string().optional(),
  action: z.string().optional(),
  operation: z.string().optional(),
  title: z.string().optional(),
  eventKind: z.string().optional(),
  event: z.string().optional(),
  kind: z.string().optional(),
  receiptType: z.string().optional(),
  sourceKind: z.string().optional(),
  actor: z.string().optional(),
  actorId: z.string().optional(),
  result: z.string().optional(),
  status: z.string().optional(),
  createdAt: isoTimestamp.optional(),
  at: isoTimestamp.optional(),
  completedAt: isoTimestamp.optional(),
  occurredAt: isoTimestamp.optional(),
  expectedRevision: z.string().optional(),
  resultRevision: z.string().optional(),
  planDigest: digestWire.optional(),
  payloadDigest: digestWire.optional(),
  validation: z.unknown().optional(),
  summary: z.string().optional(),
  beforeSummary: z.string().optional(),
  afterSummary: z.string().optional(),
  relatedOperationId: z.string().optional(),
  relatedConversationId: z.string().optional(),
  relatedApprovalId: z.string().optional(),
  relatedPlanId: z.string().optional(),
  payload: z.unknown().optional(),
})

type ReceiptValidation = Receipt['validation']

const RECEIPT_VALIDATION_MAP: Record<string, ReceiptValidation['state']> = {
  not_recorded: 'not_recorded',
  not_required: 'not_required',
  validating: 'validating',
  passed: 'validated',
  validated: 'validated',
  verified: 'validated',
  failed: 'failed',
  error: 'failed',
}

function receiptResultClaim(receiptId: string, claims: Array<[string, unknown]>): ReceiptResult {
  const present = claims.filter(([, value]) => value !== undefined)
  const malformed = present.find(([, value]) => typeof value !== 'string')
  if (malformed) failClosed(`receipt ${receiptId} has a non-text ${malformed[0]}`)
  const normalized = present
    .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
    .map(([source, value]) => {
      const result = RECEIPT_RESULT_MAP[value]
      if (!result) failClosed(`receipt ${receiptId} has unsupported ${source} "${value}"`)
      return { source, raw: value, result }
    })
  if (normalized.length === 0) failClosed(`receipt ${receiptId} has no recorded result`)
  const [first, ...rest] = normalized
  const contradiction = rest.find((claim) => claim.result !== first.result)
  if (contradiction) {
    failClosed(
      `receipt ${receiptId} has contradictory result claims ` +
        `"${first.source}:${first.raw}" and "${contradiction.source}:${contradiction.raw}"`,
    )
  }
  return first.result
}

function receiptValidationClaim(receiptId: string, value: unknown): ReceiptValidation | undefined {
  if (value === undefined) return undefined
  let rawState: unknown
  let detail = ''
  if (typeof value === 'string') {
    rawState = value
  } else if (isRecord(value)) {
    const keys = Object.keys(value)
    if (keys.some((key) => key !== 'state' && key !== 'status' && key !== 'detail')) {
      failClosed(`receipt ${receiptId} has an unsupported validation object`)
    }
    if (value.state !== undefined && value.status !== undefined && value.state !== value.status) {
      failClosed(`receipt ${receiptId} has contradictory validation state and status`)
    }
    rawState = value.state ?? value.status
    if (value.detail !== undefined && typeof value.detail !== 'string') {
      failClosed(`receipt ${receiptId} has a non-text validation detail`)
    }
    detail = typeof value.detail === 'string' ? value.detail : ''
  } else {
    failClosed(`receipt ${receiptId} has an unsupported validation value`)
  }
  if (typeof rawState !== 'string') failClosed(`receipt ${receiptId} has no validation state`)
  const state = RECEIPT_VALIDATION_MAP[rawState]
  if (!state) failClosed(`receipt ${receiptId} has unsupported validation state "${rawState}"`)
  return { state, detail }
}

function defaultValidation(result: ReceiptResult): ReceiptValidation {
  if (result === 'validated') {
    return {
      state: 'validated',
      detail: 'The receipt result explicitly records successful validation.',
    }
  }
  return {
    state: 'not_recorded',
    detail: 'No validation evidence was recorded for this receipt.',
  }
}

const HUMAN_RECEIPT_ACTIONS: Readonly<Record<string, string>> = {
  'application.install.fixture': 'Application installed',
  'backup.create': 'Backup created',
  'conversation.clear': 'Conversation cleared',
  'conversation.export': 'Conversation exported',
  'file_workspace.commitWrite': 'File change saved',
  'file_workspace.createFile': 'File created',
  'file_workspace.deletePath': 'File deleted',
  'file_workspace.renamePath': 'File renamed',
  'goal_execution.close': 'Orchestration item closed',
  'governed_run.apply': 'Application changes applied',
  'infrastructure.health': 'Infrastructure health checked',
  'libvirt.apply': 'Infrastructure changes applied',
  'libvirt.destroy': 'Virtual machine destroyed',
  'libvirt.observe': 'Infrastructure observed',
  'libvirt.restart': 'Virtual machine restarted',
  'libvirt.start': 'Virtual machine started',
  'libvirt.stop': 'Virtual machine stopped',
  'nix.validation': 'Infrastructure validation completed',
  'repository.import': 'Repository registered',
  'settings.patch': 'Settings saved',
}

function humanReceiptAction(identifier: string): string {
  const known = HUMAN_RECEIPT_ACTIONS[identifier]
  if (known) return known
  const words = identifier
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[._/:-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (!words) return 'Recorded operation'
  return `${words[0].toUpperCase()}${words.slice(1)}`
}

export function mapReceipt(payload: unknown, fallbackInstanceId?: string): Receipt {
  const wire = receiptWire.parse(payload)
  const id = wire.id ?? wire.receiptId
  if (!id) failClosed('receipt without identity')
  const instanceId = bindInstanceIdentity(
    wire.instanceId,
    fallbackInstanceId,
    `receipt ${id}`,
  )
  if (!instanceId) failClosed(`receipt ${id} has no instance identity`)
  if (wire.payload !== undefined && !isRecord(wire.payload)) {
    failClosed(`receipt ${id} has a non-object detail payload`)
  }
  const detailPayload = isRecord(wire.payload) ? wire.payload : undefined
  if (
    typeof detailPayload?.receiptId === 'string' &&
    detailPayload.receiptId !== id
  ) {
    failClosed(`receipt ${id} detail has a mismatched receipt identity`)
  }
  if (
    typeof detailPayload?.instanceId === 'string' &&
    detailPayload.instanceId !== instanceId
  ) {
    failClosed(`receipt ${id} detail has a mismatched instance identity`)
  }
  const payloadApplicationId =
    typeof detailPayload?.applicationId === 'string'
      ? detailPayload.applicationId
      : undefined
  if (
    wire.applicationId !== undefined &&
    payloadApplicationId !== undefined &&
    wire.applicationId !== payloadApplicationId
  ) {
    failClosed(`receipt ${id} detail has a mismatched application identity`)
  }
  const nestedPlanDigest =
    detailPayload?.planDigest === undefined
      ? undefined
      : digestWire.safeParse(detailPayload.planDigest)
  if (nestedPlanDigest !== undefined && !nestedPlanDigest.success) {
    failClosed(`receipt ${id} detail has a malformed plan digest`)
  }
  if (
    wire.planDigest !== undefined &&
    nestedPlanDigest?.success &&
    wire.planDigest.value !== nestedPlanDigest.data.value
  ) {
    failClosed(`receipt ${id} detail has a mismatched plan digest`)
  }
  const result = receiptResultClaim(id, [
    ['result', wire.result],
    ['status', wire.status],
    ['payload.result', detailPayload?.result],
    ['payload.status', detailPayload?.status],
  ])
  const eventKind =
    wire.eventKind ??
    wire.event ??
    wire.kind ??
    wire.action ??
    wire.operation ??
    wire.sourceKind ??
    wire.receiptType ??
    'event'
  const actionIdentifier = wire.action ?? wire.operation ?? eventKind
  const actionName =
    wire.actionName ?? wire.title ?? humanReceiptAction(actionIdentifier)
  const actor = wire.actor === 'assistant' || wire.actor === 'system' ? wire.actor : 'user'
  const topLevelValidation = receiptValidationClaim(id, wire.validation)
  const payloadValidation = receiptValidationClaim(id, detailPayload?.validation)
  if (
    topLevelValidation !== undefined &&
    payloadValidation !== undefined &&
    topLevelValidation.state !== payloadValidation.state
  ) {
    failClosed(`receipt ${id} has contradictory validation evidence`)
  }
  const validation = topLevelValidation ?? payloadValidation ?? defaultValidation(result)
  if (result === 'validated' && validation.state !== 'validated') {
    failClosed(`receipt ${id} claims validation but carries contradictory validation evidence`)
  }
  const raw = isRecord(payload) ? payload : { id }
  return {
    id,
    instanceId,
    packageId: wire.packageId ?? wire.applicationId ?? payloadApplicationId ?? 'unknown',
    actionName,
    eventKind,
    actor,
    result,
    createdAt: wire.createdAt ?? wire.at ?? wire.completedAt ?? wire.occurredAt ?? new Date().toISOString(),
    expectedRevision: wire.expectedRevision,
    resultRevision: wire.resultRevision,
    planDigest: wire.planDigest ?? (nestedPlanDigest?.success ? nestedPlanDigest.data : undefined),
    payloadDigest: wire.payloadDigest,
    validation,
    summary:
      wire.summary ??
      wire.actionName ??
      wire.title ??
      `${actionName}${/[.!?]$/.test(actionName) ? '' : '.'}`,
    beforeSummary: wire.beforeSummary,
    afterSummary: wire.afterSummary,
    relatedOperationId: wire.relatedOperationId,
    relatedConversationId: wire.relatedConversationId,
    relatedApprovalId: wire.relatedApprovalId,
    relatedPlanId: wire.relatedPlanId,
    rawJson: JSON.stringify(raw, null, 2),
  }
}

const receiptIndexWire = z.object({
  formatVersion: z.string().optional(),
  instanceId: z.string().optional(),
  receipts: z.array(z.unknown()).optional(),
  items: z.array(z.unknown()).optional(),
})

export function mapReceiptIndex(payload: unknown, instanceId: string): Receipt[] {
  if (Array.isArray(payload)) return payload.map((r) => mapReceipt(r, instanceId))
  const wire = receiptIndexWire.parse(payload)
  if (wire.formatVersion !== undefined && wire.formatVersion !== FORMAT.activityReceiptsProjection) {
    failClosed(`receipts projection formatVersion "${wire.formatVersion}"`)
  }
  bindInstanceIdentity(wire.instanceId, instanceId, 'receipts projection')
  return (wire.receipts ?? wire.items ?? []).map((r) => mapReceipt(r, instanceId))
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversation (stateport.conversation-presentation/v1)
// ─────────────────────────────────────────────────────────────────────────────

const attachmentWire = z.object({
  id: z.string().optional(),
  attachmentId: z.string().optional(),
  name: z.string().optional(),
  mediaType: z.string().optional(),
  mimeType: z.string().optional(),
  size: z.number().int().nonnegative().optional(),
  sizeBytes: z.number().int().nonnegative().optional(),
  sha256: z.string().optional(),
  digest: z.string().optional(),
  retentionClass: z.string().optional(),
})

export function mapAttachment(payload: unknown): Attachment {
  const wire = attachmentWire.parse(payload)
  const id = wire.id ?? wire.attachmentId
  if (!id) failClosed('attachment without identity')
  return {
    id,
    name: wire.name ?? id,
    mimeType: wire.mediaType ?? wire.mimeType ?? 'application/octet-stream',
    sizeBytes: wire.sizeBytes ?? wire.size ?? 0,
    state: 'ready',
    retentionNote: wire.retentionClass ? `Retention class: ${wire.retentionClass}` : undefined,
  }
}

const messageWire = z.object({
  id: z.string().optional(),
  messageId: z.string().optional(),
  externalMessageId: z.string().optional(),
  clientMessageId: z.string().optional(),
  conversationId: z.string().optional(),
  applicationId: z.string().optional(),
  instanceId: z.string().optional(),
  kind: z.string(),
  text: z.string().optional(),
  content: z.string().optional(),
  body: z.string().optional(),
  summary: z.string().optional(),
  sequence: z.number().optional(),
  channel: z.string().optional(),
  sourceChannel: z.string().optional(),
  createdAt: isoTimestamp.optional(),
  at: isoTimestamp.optional(),
  attachments: z.array(z.unknown()).optional(),
  runId: z.string().optional(),
  tool: z.string().optional(),
  proposal: z
    .object({ title: z.string().optional(), detail: z.string().optional(), actionRoute: z.string().optional() })
    .optional(),
})

const MESSAGE_KINDS = [
  'user_message',
  'assistant_message',
  'system_message',
  'run_event',
  'tool_event',
  'state_proposal_reference',
] as const

function mapMessage(
  payload: unknown,
  identity: {
    conversationId: string
    applicationId: string
    instanceId: string
  },
): ConversationMessage {
  const wire = messageWire.parse(payload)
  if (!(MESSAGE_KINDS as readonly string[]).includes(wire.kind)) {
    failClosed(`conversation message has unknown kind "${wire.kind}"`)
  }
  const id = wire.id ?? wire.messageId ?? wire.externalMessageId ?? wire.clientMessageId
  if (!id) failClosed('conversation message without identity')
  if (
    wire.conversationId !== identity.conversationId ||
    wire.applicationId !== identity.applicationId ||
    wire.instanceId !== identity.instanceId
  ) {
    failClosed(`conversation message ${id} carries missing or mismatched authority identities`)
  }
  const content = wire.text ?? wire.content ?? wire.body ?? wire.summary ?? ''
  const createdAt = wire.createdAt ?? wire.at ?? new Date().toISOString()
  const base = {
    id,
    conversationId: identity.conversationId,
    content,
    createdAt,
    attachments: (wire.attachments ?? []).map(mapAttachment),
    contextChips: [],
    toolEvents: [],
  }
  switch (wire.kind as (typeof MESSAGE_KINDS)[number]) {
    case 'user_message':
      return { ...base, role: 'user', state: 'complete' }
    case 'assistant_message':
      return { ...base, role: 'assistant', state: 'complete' }
    case 'system_message':
      return { ...base, role: 'system', state: 'complete' }
    case 'run_event':
    case 'tool_event':
      return {
        ...base,
        role: 'system',
        state: 'complete',
        toolEvents: [
          {
            id: `${id}_event`,
            kind: wire.tool ?? (wire.kind === 'run_event' ? 'run.event' : 'tool.event'),
            summary: content || (wire.kind === 'run_event' ? 'Run event' : 'Tool event'),
            state: 'completed_without_change',
            createdAt,
          },
        ],
      }
    case 'state_proposal_reference':
      return {
        ...base,
        role: 'system',
        state: 'complete',
        proposal: {
          title: wire.proposal?.title ?? 'State proposal',
          detail: wire.proposal?.detail ?? content,
          actionRoute: wire.proposal?.actionRoute,
        },
      }
  }
}

const conversationWire = z.object({
  formatVersion: z.string().optional(),
  applicationBinding: z
    .object({
      applicationId: z.string().optional(),
      instanceId: z.string(),
    })
    .strict()
    .optional(),
  thread: z
    .object({
      id: z.string().optional(),
      conversationId: z.string().optional(),
      applicationId: z.string().optional(),
      instanceId: z.string().optional(),
      title: z.string().optional(),
      channel: z.string().optional(),
      createdAt: isoTimestamp.optional(),
      updatedAt: isoTimestamp.optional(),
    })
    .optional(),
  messages: z.array(z.unknown()).optional(),
  channelBindings: z.array(z.object({
    channel: z.string().optional(),
    state: z.string().optional(),
    status: z.string().optional(),
  })).optional(),
  pendingApprovals: z.array(z.unknown()).optional(),
  receipts: z.array(z.unknown()).optional(),
  retentionStatus: z.union([
    z.string(),
    z.object({
      note: z.string().optional(),
      class: z.string().optional(),
      retention: z.string().optional(),
      storage: z.string().optional(),
      status: z.string().optional(),
    }),
  ]).optional(),
  authority: z.unknown().optional(),
})

export function mapConversation(payload: unknown, instanceId: string): Conversation {
  const wire = conversationWire.parse(payload)
  if (wire.formatVersion !== FORMAT.conversationPresentation) {
    failClosed(`conversation formatVersion "${wire.formatVersion}"`, `expected ${FORMAT.conversationPresentation}`)
  }
  if (!wire.applicationBinding?.applicationId) {
    failClosed('conversation presentation has no application binding')
  }
  bindInstanceIdentity(
    wire.applicationBinding?.instanceId,
    instanceId,
    'conversation presentation',
  )
  const thread = wire.thread
  const threadId = thread?.conversationId
  if (!threadId) failClosed('conversation presentation has no conversation identity')
  if (thread.id !== undefined && thread.id !== threadId) {
    failClosed('conversation presentation carries contradictory thread identities')
  }
  if (
    thread.applicationId !== wire.applicationBinding.applicationId ||
    thread.instanceId !== instanceId
  ) {
    failClosed('conversation thread carries missing or mismatched application identities')
  }
  const messages = (wire.messages ?? []).map((message) =>
    mapMessage(message, {
      conversationId: threadId,
      applicationId: wire.applicationBinding!.applicationId!,
      instanceId,
    }),
  )
  const webBinding = wire.channelBindings?.find((b) => b.channel === 'web') ?? wire.channelBindings?.[0]
  const bindingState = webBinding?.state ?? webBinding?.status
  const deliveryState: Conversation['deliveryState'] =
    bindingState === 'pending'
      ? 'pending'
      : bindingState === 'failed'
        ? 'failed'
        : bindingState === 'not_configured' || bindingState === 'unconfigured'
          ? 'not_configured'
          : 'delivered'
  const retention = wire.retentionStatus
  return {
    id: threadId,
    instanceId,
    title: thread.title ?? 'Conversation',
    channel: thread.channel === 'telegram' ? 'telegram' : 'web',
    deliveryState,
    retentionNote:
      typeof retention === 'string'
        ? retention
        : retention?.note ??
          (retention?.retention || retention?.storage
            ? `${retention.retention === 'explicit_capture' ? 'Explicit local retention' : retention.retention ?? 'Local retention'} · ${
                retention.storage === 'durable_local' ? 'stored on this machine' : retention.storage ?? 'local storage'
              }.`
            : 'Messages stay on this machine with the conversation.'),
    messages,
    createdAt: thread.createdAt ?? messages[0]?.createdAt ?? new Date().toISOString(),
    updatedAt: thread.updatedAt ?? messages[messages.length - 1]?.createdAt ?? new Date().toISOString(),
  }
}

/** Send-message responses: either a single acceptance or the presentation. */
export function mapSendResult(payload: unknown, instanceId: string): { userMessage: ConversationMessage; reply?: ConversationMessage } {
  if (isRecord(payload) && payload.presentation !== undefined) {
    return mapSendResult(payload.presentation, instanceId)
  }
  // Full presentation: derive the tail (last user message + following reply).
  const conversation = mapConversation(payload, instanceId)
  const userMessage = [...conversation.messages].reverse().find((m) => m.role === 'user')
  if (!userMessage) failClosed('send result presentation carried no user message')
  const after = conversation.messages.slice(conversation.messages.lastIndexOf(userMessage) + 1)
  const reply = after.find((m) => m.role === 'assistant')
  return { userMessage, reply }
}

// ─────────────────────────────────────────────────────────────────────────────
// Governed execution (actions / engines / history / runs)
// ─────────────────────────────────────────────────────────────────────────────

const actionWire = z.object({
  formatVersion: z.literal('stateport.application-action/v1').optional(),
  actionId: z.string().optional(),
  id: z.string().optional(),
  instanceId: z.string().optional(),
  displayName: z.string().optional(),
  title: z.string().optional(),
  name: z.string().optional(),
  purpose: z.string().optional(),
  description: z.string().optional(),
  engineIds: z.array(z.string()).optional(),
  engines: z.array(z.string()).optional(),
  inputSchema: z.record(z.string(), z.unknown()).optional(),
  outputSchema: z.record(z.string(), z.unknown()).optional(),
  contextPolicy: z.record(z.string(), z.unknown()).optional(),
  requiredCapabilities: z.array(z.string()).optional(),
  optionalCapabilities: z.array(z.string()).optional(),
  mutationPolicy: z.string().optional(),
  networkPolicy: z.string().optional(),
  toolPolicy: z.string().optional(),
  timeoutSeconds: z.number().int().positive().optional(),
  budgetDefaults: z.record(z.string(), z.number().int().nonnegative()).optional(),
  validationPolicy: z.record(z.string(), z.unknown()).optional(),
  supportedEngineDegradations: z.array(z.string()).optional(),
  expectedEvidenceArtifacts: z.array(z.string()).optional(),
  executorCommand: z.string().nullish(),
})

export function mapActions(payload: unknown, instanceId: string): GovernedAction[] {
  return indexPayload(payload, ['actions', 'items']).map((entry) => {
    const wire = actionWire.parse(entry)
    const id = wire.actionId ?? wire.id
    if (!id) failClosed('governed action without identity')
    const boundInstanceId = bindInstanceIdentity(
      wire.instanceId,
      instanceId,
      `governed action ${id}`,
    )
    if (!boundInstanceId) failClosed(`governed action ${id} has no instance identity`)
    return {
      id,
      instanceId: boundInstanceId,
      title: wire.displayName ?? wire.title ?? wire.name ?? id,
      description: wire.purpose ?? wire.description,
      engineIds: wire.engineIds ?? wire.engines ?? [],
      formatVersion: wire.formatVersion,
      inputSchema: wire.inputSchema,
      outputSchema: wire.outputSchema,
      contextPolicy: wire.contextPolicy,
      requiredCapabilities: wire.requiredCapabilities,
      optionalCapabilities: wire.optionalCapabilities,
      mutationPolicy: wire.mutationPolicy,
      networkPolicy: wire.networkPolicy,
      toolPolicy: wire.toolPolicy,
      timeoutSeconds: wire.timeoutSeconds,
      budgetDefaults: wire.budgetDefaults,
      validationPolicy: wire.validationPolicy,
      supportedEngineDegradations: wire.supportedEngineDegradations,
      expectedEvidenceArtifacts: wire.expectedEvidenceArtifacts,
      executorCommand: wire.executorCommand ?? undefined,
    }
  })
}

const engineWire = z.object({
  formatVersion: z.literal('stateport.execution-engine/v1').optional(),
  engineId: z.string().optional(),
  id: z.string().optional(),
  label: z.string().optional(),
  name: z.string().optional(),
  kind: z.string().optional(),
  availability: z.enum(['available', 'environment_gated', 'unavailable']).optional(),
  available: z.boolean().optional(),
  unavailableReason: z.string().optional(),
  adapterId: z.string().optional(),
  adapterVersion: z.string().optional(),
  installedVersion: z.string().optional(),
  authenticationRouteClass: z.string().optional(),
  capabilities: z.record(z.string(), z.string()).optional(),
  modelIdentity: z.string().optional(),
  productionEligible: z.boolean().optional(),
  limitations: z.array(z.string()).optional(),
})

export function mapEngines(payload: unknown): ExecutionEngine[] {
  return indexPayload(payload, ['engines', 'items']).map((entry) => {
    const wire = engineWire.parse(entry)
    const id = wire.engineId ?? wire.id
    if (!id) failClosed('execution engine without identity')
    const availability = wire.availability ?? (wire.available === false ? 'unavailable' : 'available')
    const limitations = wire.limitations ?? []
    return {
      id,
      label: wire.label ?? wire.name ?? id,
      kind: wire.kind ?? wire.adapterId ?? 'local',
      availability,
      available: availability === 'available',
      unavailableReason:
        availability === 'available'
          ? undefined
          : wire.unavailableReason ?? limitations[0] ?? 'The execution engine is not available.',
      formatVersion: wire.formatVersion,
      adapterId: wire.adapterId,
      adapterVersion: wire.adapterVersion,
      installedVersion: wire.installedVersion,
      authenticationRouteClass: wire.authenticationRouteClass,
      capabilities: wire.capabilities,
      modelIdentity: wire.modelIdentity,
      productionEligible: wire.productionEligible,
      limitations,
    }
  })
}

/** Compatibility states accepted only from older frontend-shaped fixtures. */
const LEGACY_RUN_STATE_MAP: Record<string, OperationState> = {
  draft: 'draft',
  proposed: 'proposed',
  preparing: 'preparing',
  prepared: 'prepared',
  awaiting_approval: 'awaiting_approval',
  approved: 'approved',
  queued: 'queued',
  running: 'running',
  cancelling: 'cancelling',
  paused: 'paused',
  interrupted: 'interrupted',
  applied: 'applied',
  validating: 'validating',
  validated: 'validated',
  completed_without_change: 'completed_without_change',
  rejected: 'rejected',
  cancelled: 'cancelled',
  canceled: 'cancelled',
  blocked: 'blocked',
  unavailable: 'unavailable',
  failed: 'failed',
  human_accepted: 'human_accepted',
}

const runStatusWire = z.enum([
  'requested',
  'planned',
  'awaiting_approval',
  'approved',
  'preparing',
  'prepared',
  'running',
  'awaiting_tool_approval',
  'cancelling',
  'cancelled',
  'interrupted',
  'timed_out',
  'failed',
  'completed',
  'result_validating',
  'result_rejected',
  'state_change_proposed',
  'state_change_approved',
  'state_change_rejected',
  'applying',
  'applied',
  'apply_failed',
  'archived',
])

const runLifecycleWire = z.enum([
  'DRAFT',
  'COMPILED',
  'BLOCKED_CAPABILITY',
  'AWAITING_RUN_APPROVAL',
  'APPROVED',
  'STARTING',
  'RUNNING',
  'SUCCEEDED',
  'FAILED',
  'CANCELLED',
  'INTERRUPTED',
  'TIMED_OUT',
  'RESULT_VALIDATED',
  'NO_MUTATION',
  'PROPOSAL_CREATED',
  'AWAITING_PROPOSAL_APPROVAL',
  'PROPOSAL_REJECTED',
  'APPLYING',
  'APPLIED',
  'POST_VALIDATED',
  'CLOSED',
  'ROLLED_BACK',
])

const RUN_STATUS_PRESENTATION: Record<RunStatus, OperationState> = {
  requested: 'draft',
  planned: 'preparing',
  awaiting_approval: 'awaiting_approval',
  approved: 'approved',
  preparing: 'preparing',
  prepared: 'prepared',
  running: 'running',
  awaiting_tool_approval: 'awaiting_approval',
  cancelling: 'cancelling',
  cancelled: 'cancelled',
  interrupted: 'interrupted',
  timed_out: 'failed',
  failed: 'failed',
  completed: 'completed_without_change',
  result_validating: 'validating',
  result_rejected: 'rejected',
  state_change_proposed: 'proposed',
  state_change_approved: 'approved',
  state_change_rejected: 'rejected',
  applying: 'running',
  applied: 'applied',
  apply_failed: 'failed',
  archived: 'completed_without_change',
}

const runEventWire = z.object({
  type: z.string(),
  at: isoTimestamp.optional(),
  from: z.string().optional(),
  to: z.string().optional(),
  fromLifecycle: runLifecycleWire.optional(),
  toLifecycle: runLifecycleWire.optional(),
  actor: z.string().optional(),
  reason: z.string().nullish(),
})

const exactRunDigestWire = z.string().regex(/^sha256:[0-9a-f]{64}$/)
const exactRunGitWire = z.string().regex(/^[0-9a-f]{40,64}$/)
const runClosureReceiptWire = z
  .object({
    formatVersion: z.literal('stateport.governed-run-closure-receipt/v1'),
    receiptId: z
      .string()
      .regex(/^governed-run\.[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\.[0-9a-f]{12}$/),
    receiptType: z.literal('stateport.governed-run-closure-receipt/v1'),
    action: z.literal('governed_run.apply'),
    status: z.literal('applied'),
    createdAt: isoTimestamp,
    sourceKind: z.literal('governed_run'),
    actor: z.literal('system'),
    applicationId: z.string().min(1),
    instanceId: z.string().min(1),
    runId: z.string().min(1),
    actionId: z.string().min(1),
    engineId: z.string().min(1),
    runSpecDigest: exactRunDigestWire,
    descriptorDigest: exactRunDigestWire,
    actionContractDigest: exactRunDigestWire,
    sourceIdentityDigest: exactRunDigestWire,
    proposalId: z.string().min(1),
    proposalDigest: exactRunDigestWire,
    proposalApprovalDigest: exactRunDigestWire,
    baseGit: exactRunGitWire,
    finalGit: exactRunGitWire,
    canonicalStateBefore: exactRunDigestWire,
    canonicalStateAfter: exactRunDigestWire,
    applicationReceiptDigest: exactRunDigestWire,
    appliedRunBundleDigest: exactRunDigestWire,
    validation: z
      .object({
        state: z.literal('validated'),
        detail: z.string().min(1),
      })
      .strict(),
    postApplyValidation: z
      .object({
        status: z.literal('passed'),
        commandDigest: exactRunDigestWire,
      })
      .passthrough(),
    claimState: z
      .object({
        applied: z.literal(true),
        locallyValidated: z.literal(true),
        humanAccepted: z.literal(false),
        remotelyAccepted: z.literal(false),
      })
      .strict(),
    summary: z.string().min(1),
    beforeSummary: z.string().min(1),
    afterSummary: z.string().min(1),
  })
  .strict()

const runWire = z.object({
  formatVersion: z.literal('stateport.governed-action-run/v1').optional(),
  runId: z.string().optional(),
  id: z.string().optional(),
  instanceId: z.string().optional(),
  applicationId: z.string().optional(),
  actionId: z.string().optional(),
  engineId: z.string().optional(),
  engine: z
    .object({
      engineId: z.string(),
    })
    .passthrough()
    .optional(),
  status: runStatusWire.optional(),
  state: z.string().optional(),
  lifecycleState: runLifecycleWire.optional(),
  lifecycleVersion: z.literal('stateport.run-lifecycle/v1').optional(),
  revision: z.number().int().nonnegative().optional(),
  inputs: z.record(z.string(), z.unknown()).optional(),
  proposalDigest: digestWire.optional(),
  proposal: z.record(z.string(), z.unknown()).nullish(),
  proposalApproval: z.record(z.string(), z.unknown()).optional(),
  runSpecDigest: digestWire.optional(),
  runSpec: z.record(z.string(), z.unknown()).optional(),
  descriptorDigest: exactRunDigestWire.optional(),
  actionContractDigest: exactRunDigestWire.optional(),
  negotiation: z.record(z.string(), z.unknown()).optional(),
  executionGate: z.record(z.string(), z.unknown()).nullish(),
  result: z.record(z.string(), z.unknown()).nullish(),
  postApplyValidation: z.record(z.string(), z.unknown()).optional(),
  rollback: z.record(z.string(), z.unknown()).optional(),
  receipt: z.record(z.string(), z.unknown()).optional(),
  closureReceipt: runClosureReceiptWire.optional(),
  receiptId: z.string().optional(),
  canonicalStateBefore: exactRunDigestWire.optional(),
  canonicalStateAfter: exactRunDigestWire.optional(),
  baseGit: exactRunGitWire.optional(),
  appliedRunBundle: z
    .object({
      formatVersion: z.literal('stateport.run-bundle/v1'),
      runId: z.string(),
      contentDigest: exactRunDigestWire,
    })
    .passthrough()
    .optional(),
  events: z.array(runEventWire).optional(),
  requestedAt: isoTimestamp.optional(),
  createdAt: isoTimestamp.optional(),
  updatedAt: isoTimestamp.optional(),
})

export function mapRun(payload: unknown, fallbackInstanceId?: string): RunRecord {
  if (!isRecord(payload)) failClosed('run projection was not an object')
  const envelope = isRecord(payload.run) ? payload : undefined
  const wire = runWire.parse(envelope?.run ?? payload)
  const id = wire.runId ?? wire.id
  if (!id) failClosed('run projection without identity')
  const instanceId = bindInstanceIdentity(
    wire.instanceId,
    fallbackInstanceId,
    `run ${id}`,
  )
  if (!instanceId) failClosed(`run ${id} has no instance identity`)
  const engineId = wire.engine?.engineId ?? wire.engineId
  if (!engineId) failClosed(`run ${id} has no execution-engine identity`)
  if (!wire.actionId) failClosed(`run ${id} has no action identity`)
  if (wire.revision === undefined) failClosed(`run ${id} has no revision`)
  if (wire.formatVersion && !wire.lifecycleState) {
    failClosed(`run ${id} has no explicit lifecycle state`)
  }
  let state: OperationState
  if (wire.status) {
    state = RUN_STATUS_PRESENTATION[wire.status]
  } else if (wire.state && LEGACY_RUN_STATE_MAP[wire.state]) {
    state = LEGACY_RUN_STATE_MAP[wire.state]
  } else {
    failClosed(`run ${id} has no recognized status`, wire.state)
  }
  const events = wire.events?.map((event) => ({
    type: event.type,
    at: event.at,
    from: event.from,
    to: event.to,
    fromLifecycle: event.fromLifecycle as RunLifecycleState | undefined,
    toLifecycle: event.toLifecycle as RunLifecycleState | undefined,
    actor: event.actor,
    reason: event.reason ?? undefined,
  }))
  const createdAt = wire.requestedAt ?? wire.createdAt
  if (!createdAt) failClosed(`run ${id} has no creation timestamp`)
  const lastEventAt = [...(events ?? [])].reverse().find((event) => event.at)?.at
  const closureReceipt = wire.closureReceipt
  if (closureReceipt) {
    const proposalId =
      wire.proposal && typeof wire.proposal.proposalId === 'string'
        ? wire.proposal.proposalId
        : undefined
    const approvalDigest =
      typeof wire.proposalApproval?.approvalDigest === 'string'
        ? wire.proposalApproval.approvalDigest
        : undefined
    const applicationReceipt = wire.receipt
    const validationCommandDigest =
      typeof wire.postApplyValidation?.commandDigest === 'string'
        ? wire.postApplyValidation.commandDigest
        : undefined
    if (
      wire.status !== 'applied' ||
      wire.lifecycleState !== 'CLOSED' ||
      wire.receiptId !== closureReceipt.receiptId ||
      closureReceipt.runId !== id ||
      closureReceipt.instanceId !== instanceId ||
      closureReceipt.applicationId !== wire.applicationId ||
      closureReceipt.actionId !== wire.actionId ||
      closureReceipt.engineId !== engineId ||
      closureReceipt.runSpecDigest !== wire.runSpecDigest?.value ||
      closureReceipt.descriptorDigest !== wire.descriptorDigest ||
      closureReceipt.actionContractDigest !== wire.actionContractDigest ||
      closureReceipt.proposalId !== proposalId ||
      closureReceipt.proposalDigest !== wire.proposalDigest?.value ||
      closureReceipt.proposalApprovalDigest !== approvalDigest ||
      closureReceipt.baseGit !== wire.baseGit ||
      closureReceipt.finalGit !== wire.baseGit ||
      closureReceipt.canonicalStateBefore !== wire.canonicalStateBefore ||
      closureReceipt.canonicalStateAfter !== wire.canonicalStateAfter ||
      closureReceipt.appliedRunBundleDigest !== wire.appliedRunBundle?.contentDigest ||
      wire.appliedRunBundle?.runId !== id ||
      validationCommandDigest !== closureReceipt.postApplyValidation.commandDigest ||
      wire.postApplyValidation?.status !== 'passed' ||
      applicationReceipt?.proposalId !== closureReceipt.proposalId ||
      applicationReceipt?.postStateDigest !== closureReceipt.canonicalStateAfter ||
      applicationReceipt?.baseGit !== closureReceipt.baseGit ||
      applicationReceipt?.finalGit !== closureReceipt.finalGit
    ) {
      failClosed(`run ${id} closure receipt identity does not match the governed run`)
    }
  } else if (wire.status === 'applied' && wire.lifecycleState === 'CLOSED') {
    failClosed(`run ${id} is closed after apply but carries no closure receipt`)
  } else if (wire.receiptId !== undefined) {
    failClosed(`run ${id} carries a receipt identity before authoritative closure`)
  }
  const receiptId = closureReceipt?.receiptId
  const envelopeGate = envelope && isRecord(envelope.executionGate) ? envelope.executionGate : undefined
  return {
    id,
    instanceId,
    actionId: wire.actionId,
    engineId,
    state,
    status: wire.status as RunStatus | undefined,
    lifecycleState: wire.lifecycleState as RunLifecycleState | undefined,
    lifecycleVersion: wire.lifecycleVersion,
    formatVersion: wire.formatVersion,
    revision: wire.revision,
    inputs: wire.inputs ?? {},
    proposalDigest: wire.proposalDigest,
    proposal: wire.proposal ?? undefined,
    runSpecDigest: wire.runSpecDigest,
    runSpec: wire.runSpec,
    negotiation: wire.negotiation,
    executionGate: wire.executionGate ?? envelopeGate,
    result: wire.result ?? undefined,
    postApplyValidation: wire.postApplyValidation,
    rollback: wire.rollback,
    receipt: wire.receipt,
    closureReceipt,
    receiptId,
    events,
    approvalRequired:
      envelope && typeof envelope.approvalRequired === 'boolean'
        ? envelope.approvalRequired
        : undefined,
    createdAt,
    updatedAt: wire.updatedAt ?? lastEventAt ?? createdAt,
  }
}

export function mapRunHistory(payload: unknown, instanceId: string): RunRecord[] {
  return indexPayload(payload, ['runs', 'items', 'history']).map((r) => mapRun(r, instanceId))
}

const runBundleWire = z.object({
  runId: z.string(),
  applied: z.boolean(),
  bundle: z.object({
    formatVersion: z.literal('stateport.run-bundle/v1'),
    runId: z.string(),
    path: z.string().optional(),
    contentDigest: digestWire,
    fileCount: z.number().int().nonnegative(),
  }),
  verification: z.object({
    formatVersion: z.literal('stateport.run-bundle/v1'),
    runId: z.string(),
    contentDigest: digestWire,
    verified: z.literal(true),
    fileCount: z.number().int().nonnegative(),
  }),
})

export function mapRunBundle(payload: unknown, expectedRunId?: string): RunBundle {
  const wire = runBundleWire.parse(payload)
  if (
    wire.bundle.runId !== wire.runId ||
    wire.verification.runId !== wire.runId ||
    (expectedRunId !== undefined && wire.runId !== expectedRunId)
  ) {
    failClosed('RunBundle carried mismatched run identities')
  }
  if (
    wire.bundle.contentDigest.value !== wire.verification.contentDigest.value ||
    wire.bundle.fileCount !== wire.verification.fileCount
  ) {
    failClosed('RunBundle verification identity did not match the bundle')
  }
  return {
    runId: wire.runId,
    applied: wire.applied,
    formatVersion: wire.bundle.formatVersion,
    contentDigest: wire.bundle.contentDigest,
    fileCount: wire.bundle.fileCount,
    verified: wire.verification.verified,
    // The live endpoint does not expose event or receipt indexes. In
    // particular, its local filesystem `bundle.path` is deliberately dropped.
    events: [],
    receiptIds: [],
  }
}

const stateBenchRowWire = z.object({
  formatVersion: z.literal('statebench.run-bundle-row/v1'),
  integrityStatus: z.literal('verified'),
  authoritative: z.literal(false),
  producerClaimsTrusted: z.literal(false),
  bundleDigest: digestWire,
  runId: z.string(),
  applicationId: z.string(),
  engineId: z.string(),
  adapterId: z.string(),
  status: runStatusWire,
  statePreserved: z.boolean(),
  capabilityDegradations: z.array(z.record(z.string(), z.unknown())),
  acceptedRun: z.boolean(),
  usageAvailable: z.boolean().nullable(),
  latencyMs: z.number().finite().nonnegative().nullable(),
  unauthorizedMutations: z.number().int().nonnegative(),
  bundleFileCount: z.number().int().nonnegative(),
})

const stateBenchWire = z.object({
  runId: z.string(),
  applied: z.boolean(),
  row: stateBenchRowWire,
})

export function mapStateBench(payload: unknown, subjectId: string): StateBenchResult {
  const wire = stateBenchWire.parse(payload)
  if (wire.runId !== subjectId || wire.row.runId !== subjectId) {
    failClosed('StateBench evidence carried a mismatched run identity')
  }
  const row = {
    ...wire.row,
    status: wire.row.status as RunStatus,
  }
  return {
    subjectId,
    applied: wire.applied,
    row,
    // This is the run's exact status projected for the semantic label, not an
    // aggregate benchmark verdict.
    state: RUN_STATUS_PRESENTATION[row.status],
    checks: [
      {
        id: 'bundle_integrity',
        title: 'RunBundle integrity',
        state: 'validated',
        detail: 'The recorded RunBundle passed its checksum verification.',
      },
      {
        id: 'state_preservation',
        title: 'Canonical state preservation',
        state: row.statePreserved ? 'validated' : 'failed',
      },
      {
        id: 'capability_negotiation',
        title: 'Capability negotiation',
        state: row.acceptedRun ? 'validated' : 'failed',
      },
      {
        id: 'unauthorized_mutations',
        title: 'Unauthorized mutations',
        state: row.unauthorizedMutations === 0 ? 'validated' : 'failed',
        detail:
          row.unauthorizedMutations === 0
            ? 'None recorded.'
            : `${row.unauthorizedMutations} unauthorized mutation(s) recorded.`,
      },
    ],
  }
}

export function mapPlatformStateBench(payload: unknown): PlatformStateBenchView {
  const wire = schemas.platformStateBenchView.parse(payload)
  if (wire.verifiedRowCount < wire.rows.length) {
    failClosed('StateBench verified-row count was smaller than the returned row set')
  }
  if (wire.truncated !== (wire.verifiedRowCount > wire.rows.length)) {
    failClosed('StateBench truncation state did not match the verified-row count')
  }
  const runIds = new Set<string>()
  const bundleDigests = new Set<string>()
  for (const row of wire.rows) {
    if (runIds.has(row.runId) || bundleDigests.has(row.bundleDigest)) {
      failClosed('StateBench returned duplicate run or bundle identities')
    }
    runIds.add(row.runId)
    bundleDigests.add(row.bundleDigest)
  }
  return wire
}

// ─────────────────────────────────────────────────────────────────────────────
// Context lifecycle
// ─────────────────────────────────────────────────────────────────────────────

const contextModeWire = z.enum(['faster', 'balanced', 'deeper'])

const contextEffectivePolicyWire = z
  .object({
    formatVersion: z.literal(FORMAT.contextEffectivePolicy),
    sourcePolicies: z.array(
      z
        .object({
          scope: z.string().min(1),
          policyId: z.string().min(1),
          digest: z.string().min(8),
        })
        .strict(),
    ),
    unresolvedPolicyScopes: z.array(z.string().min(1)),
    budget: z
      .object({
        maximumInputTokens: z.number().int().positive(),
        preferredInputTokens: z.number().int().positive(),
      })
      .strict(),
    compression: z
      .object({
        mode: z.string().min(1),
        triggerRatio: z.number().min(0).max(1),
        preserve: z.array(z.string().min(1)),
      })
      .strict(),
    handoff: z
      .object({
        mode: z.string().min(1),
        triggerRatio: z.number().min(0).max(1),
        createArtifact: z.boolean(),
        requireReceipt: z.boolean(),
      })
      .strict(),
    session: z.object({ resumeOnlyWhen: z.array(z.string().min(1)) }).strict(),
    contextCategories: z
      .object({
        included: z.array(z.string().min(1)),
        excluded: z.array(z.string().min(1)),
      })
      .strict(),
    bindingReasons: z.record(z.string(), z.array(z.string().min(1))),
    authorityClassification: z.literal('operational_noncanonical'),
    canonicalStateMutation: z.literal(false),
    effectivePolicyDigest: z.string().min(8),
  })
  .strict()

const contextUsageWire = z
  .object({
    formatVersion: z.literal(FORMAT.contextUsage),
    inputTokens: z.number().int().min(0).max(2_000_000).nullable(),
    quality: z.enum(['observed', 'estimated', 'unavailable']),
    source: z.enum(['provider_reported', 'stateport_estimator', 'unavailable']),
  })
  .strict()

const contextGitIdentityWire = z
  .object({
    repositoryId: z.string().min(1),
    branch: z.string().min(1),
    baseSha: z.string().min(8),
    headSha: z.string().min(8),
    treeSha: z.string().min(8),
    worktreeStatusDigest: z.string().min(8),
    worktreeClean: z.boolean(),
  })
  .strict()

const contextLifecycleWire = z
  .object({
    formatVersion: z.literal(FORMAT.contextLifecycleView),
    instanceId: z.string().min(1),
    preference: z
      .object({
        mode: contextModeWire,
        availableModes: z.array(
          z
            .object({
              id: contextModeWire,
              label: z.string().min(1),
              description: z.string().min(1),
            })
            .strict(),
        ),
        rawPromptFieldsAllowed: z.boolean(),
      })
      .strict(),
    effectivePolicy: contextEffectivePolicyWire,
    usage: contextUsageWire,
    usageDisplay: z.string().min(1),
    gitIdentity: contextGitIdentityWire.nullable(),
    gitIdentityReason: z.string().min(1).nullable(),
    continuity: z
      .object({
        available: z.boolean(),
        reasonCode: z.string().min(1).nullable(),
        manualCompactAvailable: z.boolean(),
        manualHandoffAvailable: z.boolean(),
        continuityDigest: z.string().min(8).nullable(),
        conversationId: z.string().min(1).nullable(),
        workstreamId: z.string().min(1).nullable(),
        expectedBaseSha: z.string().min(8).nullable(),
        expectedPolicyDigest: z.string().min(8).nullable(),
      })
      .strict(),
    storedRecordCount: z.number().int().nonnegative(),
    defaultsEvidence: z.literal('candidate_not_benchmarked'),
    authorityClassification: z.literal('operational_noncanonical'),
    canonicalStateMutation: z.literal(false),
  })
  .strict()

export function mapContextLifecycle(payload: unknown, instanceId: string): ContextLifecycle {
  const parsed = contextLifecycleWire.safeParse(payload)
  if (!parsed.success) {
    failClosed(
      'context lifecycle projection failed validation',
      parsed.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join('\n'),
    )
  }
  const wire = parsed.data
  const continuity = wire.continuity
  if (wire.instanceId !== instanceId) {
    failClosed(
      `context lifecycle instance identity "${wire.instanceId}"`,
      `expected ${instanceId}`,
    )
  }
  const expectedUsageSource = {
    observed: 'provider_reported',
    estimated: 'stateport_estimator',
    unavailable: 'unavailable',
  }[wire.usage.quality]
  if (wire.usage.source !== expectedUsageSource) {
    failClosed('context usage source does not match its accounting quality')
  }
  if (
    (wire.usage.quality === 'unavailable') !==
    (wire.usage.inputTokens === null)
  ) {
    failClosed('context usage availability contradicts its token value')
  }
  if (
    wire.effectivePolicy.budget.preferredInputTokens >
    wire.effectivePolicy.budget.maximumInputTokens
  ) {
    failClosed('context preferred budget exceeds its maximum')
  }
  if (continuity.available) {
    if (
      !continuity.continuityDigest ||
      !continuity.conversationId ||
      !continuity.expectedBaseSha ||
      !continuity.expectedPolicyDigest ||
      !wire.gitIdentity
    ) {
      failClosed('available context continuity is missing an exact identity')
    }
    if (
      continuity.expectedPolicyDigest !==
      wire.effectivePolicy.effectivePolicyDigest
    ) {
      failClosed('context continuity policy identity does not match the effective policy')
    }
    if (continuity.expectedBaseSha !== wire.gitIdentity.headSha) {
      failClosed('context continuity base does not match the current Git identity')
    }
  } else if (
    continuity.manualCompactAvailable ||
    continuity.manualHandoffAvailable
  ) {
    failClosed('unavailable context continuity exposes an active transition')
  }
  return {
    formatVersion: FORMAT.contextLifecycleView,
    instanceId,
    policyDigest: {
      algorithm: 'sha256',
      value: wire.effectivePolicy.effectivePolicyDigest,
    },
    effectivePolicy: wire.effectivePolicy,
    preference: wire.preference.mode,
    availableModes: wire.preference.availableModes,
    rawPromptFieldsAllowed: wire.preference.rawPromptFieldsAllowed,
    usageDisplay: wire.usageDisplay,
    usage: wire.usage,
    gitIdentity: wire.gitIdentity,
    gitIdentityReason: wire.gitIdentityReason,
    continuity: {
      ...continuity,
    },
    storedRecordCount: wire.storedRecordCount,
    defaultsEvidence: wire.defaultsEvidence,
    authorityClassification: wire.authorityClassification,
    canonicalStateMutation: wire.canonicalStateMutation,
    segments: [],
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// CTO goal execution (stateport.goal-execution-view/v1) → 13-stage session
// ─────────────────────────────────────────────────────────────────────────────

const GOAL_STATES = [
  'not_prepared',
  'off',
  'proposal_ready',
  'approved',
  'awaiting_independent_review',
  'independently_reviewed',
  'closed',
  'stopped',
] as const

type GoalState = (typeof GOAL_STATES)[number]

const goalDigestWire = z.string().regex(/^sha256:[0-9a-f]{64}$/)
const gitIdentityWire = z.string().regex(/^[0-9a-f]{40,64}$/)
const goalBudgetWire = z.object({
  token: z.number().int().nonnegative().optional(),
  costMinor: z.number().int().nonnegative().optional(),
  timeSeconds: z.number().int().nonnegative().optional(),
  steps: z.number().int().nonnegative().optional(),
})

const goalBackendAvailabilityWire = z.object({
  status: z.enum(['available', 'unavailable']),
  backendId: z.string().optional(),
  testOnly: z.boolean().optional(),
  code: z.string().optional(),
  message: z.string().optional(),
  nextAction: z.string().optional(),
})

const goalExecutionWire = z.object({
  formatVersion: z.string().optional(),
  instanceId: z.string().min(1),
  applicationId: z.string().min(1).optional(),
  state: z.string(),
  mode: z.string().optional(),
  revision: z.number().int().nonnegative().optional(),
  recordedAt: isoTimestamp.optional(),
  objective: z.string().optional(),
  // Backend identity is retained end-to-end: the view, the frontend types,
  // and the durable receipt must all carry exactly which backend (if any)
  // stood behind a projection, and a test-only backend stays labelled.
  backendId: z.string().nullish(),
  providerExecution: z.boolean().optional(),
  canonicalStateEffect: z.string().optional(),
  backendAvailability: goalBackendAvailabilityWire.optional(),
  currentIdentity: z
    .object({
      baseCommit: gitIdentityWire.optional(),
      baseTree: gitIdentityWire.optional(),
      repositoryClean: z.boolean().optional(),
      reasonCode: z.string().optional(),
    })
    .optional(),
  slice: z
    .object({
      planId: z.string().optional(),
      baseCommit: gitIdentityWire.optional(),
      baseTree: gitIdentityWire.optional(),
      requiredPermissions: z.array(z.string()).optional(),
      maximumBudget: goalBudgetWire.optional(),
      validationCommands: z.array(z.string()).optional(),
      networkPolicy: z.string().optional(),
      planDigest: goalDigestWire.optional(),
    })
    .nullish(),
  selectedItem: z
    .object({
      objective: z.string().optional(),
      scope: z.array(z.string()).optional(),
      requiredPermissions: z.array(z.string()).optional(),
    })
    .nullish(),
  delegation: z
    .object({
      implementerActor: z.string().optional(),
      reviewerActor: z.string().optional(),
      readScope: z.array(z.string()).optional(),
      writeScope: z.array(z.string()).optional(),
    })
    .nullish(),
  executionResult: z
    .object({
      executionResultDigest: goalDigestWire.optional(),
      usedBudget: goalBudgetWire.optional(),
      testsPassed: z.boolean().optional(),
      repositoryClean: z.boolean().optional(),
    })
    .nullish(),
  review: z
    .object({
      reviewDigest: goalDigestWire.optional(),
      disposition: z.string().optional(),
      reviewerActor: z.string().optional(),
    })
    .nullish(),
  receipt: z
    .object({
      receiptId: z.string(),
      formatVersion: z.string().optional(),
    })
    .passthrough()
    .nullish(),
  baseIdentity: z
    .object({
      name: z.string().optional(),
      branch: z.string().optional(),
      commit: z.string().optional(),
      revision: z.string().optional(),
      tree: z.string().optional(),
      clean: z.boolean().optional(),
      dirty: z.boolean().optional(),
    })
    .optional(),
  scope: z.array(z.string()).optional(),
  permissions: z.array(z.string()).optional(),
  budget: z
    .object({
      maxOperations: z.number().optional(),
      maxMinutes: z.number().optional(),
      usedOperations: z.number().optional(),
      usedMinutes: z.number().optional(),
    })
    .optional(),
  implementer: z.string().optional(),
  reviewer: z.string().optional(),
  resultSummary: z.string().optional(),
  planDigest: digestWire.optional(),
  executionResultDigest: digestWire.optional(),
  reviewDigest: digestWire.optional(),
  receiptId: z.string().optional(),
  createdAt: isoTimestamp.optional(),
  updatedAt: isoTimestamp.optional(),
})

const GOAL_STAGE_MAP: Record<GoalState, { stage: OrchestrationStage; state: OperationState; active: boolean }> = {
  not_prepared: { stage: 'enter_objective', state: 'draft', active: false },
  off: { stage: 'select_mode', state: 'cancelled', active: false },
  proposal_ready: { stage: 'review_base', state: 'prepared', active: true },
  approved: { stage: 'run', state: 'approved', active: true },
  // Goal execution is a provider-free, staging-only proof. The backend
  // explicitly records canonicalStateEffect="none": executing it never means
  // that StatePort applied canonical state, and an independent machine review
  // is not human acceptance.
  awaiting_independent_review: {
    stage: 'independent_review',
    state: 'completed_without_change',
    active: true,
  },
  independently_reviewed: { stage: 'close', state: 'validated', active: true },
  closed: { stage: 'receipt', state: 'validated', active: false },
  stopped: { stage: 'run', state: 'cancelled', active: false },
}

export interface GoalExecutionView {
  session: OrchestrationSession | null
  instanceId: string
  applicationId?: string
  /** The raw backend state — retained for transitions and honesty checks. */
  goalState: GoalState
  revision: number
  baseCommit?: string
  planDigest?: string
  executionResultDigest?: string
  reviewDigest?: string
  receipt?: unknown
  recordedAt?: string
  /** Exact backend behind the projection; null/undefined means none bound. */
  backendId?: string | null
  /** True only when a real provider backend executed — never for test-only. */
  providerExecution: boolean
  /** The backend's own declaration; "none" means no canonical state changed. */
  canonicalStateEffect?: string
  /**
   * Typed availability of governed execution. When `unavailable` the UI
   * must show the plain reason and next action instead of offering active
   * orchestration that the backend would always refuse.
   */
  backendAvailability?: {
    status: 'available' | 'unavailable'
    backendId?: string
    testOnly?: boolean
    code?: string
    message?: string
    nextAction?: string
  }
}

export function mapGoalExecution(
  payload: unknown,
  expectedInstanceId: string,
  expectedApplicationId?: string,
): GoalExecutionView {
  const parsed = goalExecutionWire.safeParse(payload)
  if (!parsed.success) {
    failClosed(
      'goal-execution response did not match the current contract',
      parsed.error.issues.map((issue) => issue.path.join('.') || 'projection').join(', '),
    )
  }
  const wire = parsed.data
  if (wire.formatVersion !== FORMAT.goalExecutionView) {
    failClosed(
      `goal-execution formatVersion "${wire.formatVersion ?? 'missing'}"`,
      `expected ${FORMAT.goalExecutionView}`,
    )
  }
  if (wire.instanceId !== expectedInstanceId) {
    failClosed(
      `goal-execution instance identity "${wire.instanceId}"`,
      `expected ${expectedInstanceId}`,
    )
  }
  if (!(GOAL_STATES as readonly string[]).includes(wire.state)) {
    failClosed(`goal-execution reported unknown state "${wire.state}"`)
  }
  const goalState = wire.state as GoalState
  if (goalState !== 'not_prepared' && wire.applicationId === undefined) {
    failClosed(`goal-execution state "${goalState}" carries no application identity`)
  }
  if (
    expectedApplicationId !== undefined &&
    wire.applicationId !== expectedApplicationId
  ) {
    failClosed(
      `goal-execution application identity "${wire.applicationId ?? 'missing'}"`,
      `expected ${expectedApplicationId}`,
    )
  }
  const mapped = GOAL_STAGE_MAP[goalState]
  const mode =
    wire.mode === 'advisory' || wire.mode === 'assisted' || wire.mode === 'managed_approved_queue'
      ? wire.mode
      : ('off' as const)
  const createdAt = wire.createdAt ?? wire.recordedAt ?? new Date().toISOString()
  const maximumBudget = wire.slice?.maximumBudget
  const usedBudget = wire.executionResult?.usedBudget
  const selectedScope = wire.selectedItem?.scope
  const delegatedScope = [
    ...(wire.delegation?.readScope ?? []),
    ...(wire.delegation?.writeScope ?? []),
  ]
  const scope = selectedScope?.length ? selectedScope : [...new Set(delegatedScope)]
  const testsPassed = wire.executionResult?.testsPassed
  const repositoryClean = wire.executionResult?.repositoryClean
  const resultSummary =
    wire.resultSummary ??
    (testsPassed !== undefined || repositoryClean !== undefined
      ? `${testsPassed ? 'Validation passed' : 'Validation did not pass'}; ${
          repositoryClean ? 'the repository remained clean' : 'repository drift was detected'
        }.`
      : wire.review?.disposition
        ? `Independent review: ${wire.review.disposition.replaceAll('_', ' ')}.`
        : undefined)
  const session: OrchestrationSession = {
    id: `orch_${wire.instanceId}`,
    instanceId: wire.instanceId,
    objective: wire.objective ?? wire.selectedItem?.objective ?? '',
    mode,
    stage: mapped.stage,
    state: mapped.state,
    baseIdentity: {
      name: wire.baseIdentity?.name ?? 'repository',
      branch: wire.baseIdentity?.branch ?? 'main',
      revision:
        wire.baseIdentity?.revision ??
        wire.baseIdentity?.commit ??
        wire.slice?.baseCommit ??
        wire.currentIdentity?.baseCommit ??
        '',
      clean:
        wire.currentIdentity?.repositoryClean ??
        wire.baseIdentity?.clean ??
        (wire.baseIdentity?.dirty !== undefined ? !wire.baseIdentity.dirty : true),
    },
    scope: wire.scope ?? scope,
    permissions:
      wire.permissions ??
      wire.slice?.requiredPermissions ??
      wire.selectedItem?.requiredPermissions ??
      [],
    budget: {
      maxOperations: wire.budget?.maxOperations ?? maximumBudget?.steps ?? 0,
      maxMinutes:
        wire.budget?.maxMinutes ??
        (maximumBudget?.timeSeconds !== undefined ? Math.ceil(maximumBudget.timeSeconds / 60) : 0),
      usedOperations: wire.budget?.usedOperations ?? usedBudget?.steps ?? 0,
      usedMinutes:
        wire.budget?.usedMinutes ??
        (usedBudget?.timeSeconds !== undefined ? Math.ceil(usedBudget.timeSeconds / 60) : 0),
    },
    implementer: wire.implementer ?? wire.delegation?.implementerActor ?? 'stateport',
    reviewer: wire.reviewer ?? wire.review?.reviewerActor ?? wire.delegation?.reviewerActor ?? 'independent',
    resultSummary,
    receiptId: wire.receiptId ?? wire.receipt?.receiptId,
    createdAt,
    updatedAt: wire.updatedAt ?? wire.recordedAt ?? createdAt,
  }
  return {
    session: mapped.active || goalState === 'closed' ? session : null,
    instanceId: wire.instanceId,
    applicationId: wire.applicationId,
    goalState,
    revision: wire.revision ?? 0,
    baseCommit: wire.currentIdentity?.baseCommit ?? wire.slice?.baseCommit,
    planDigest: wire.slice?.planDigest,
    executionResultDigest: wire.executionResult?.executionResultDigest,
    reviewDigest: wire.review?.reviewDigest,
    receipt: wire.receipt ?? undefined,
    recordedAt: wire.recordedAt,
    backendId: wire.backendId,
    providerExecution: wire.providerExecution === true,
    canonicalStateEffect: wire.canonicalStateEffect,
    backendAvailability: wire.backendAvailability,
  }
}

/** Normalize the closure receipt embedded in a goal-execution projection. */
export function mapGoalExecutionReceipt(
  payload: unknown,
  instanceId: string,
  expectedApplicationId?: string,
): Receipt | null {
  const view = mapGoalExecution(payload, instanceId, expectedApplicationId)
  if (!view.receipt || typeof view.receipt !== 'object') return null
  const receipt = view.receipt as Record<string, unknown>
  if (
    view.applicationId !== undefined &&
    receipt.applicationId !== view.applicationId
  ) {
    failClosed(
      `goal-execution receipt application identity "${String(receipt.applicationId ?? 'missing')}"`,
      `expected ${view.applicationId}`,
    )
  }
  return mapReceipt({
    ...view.receipt,
    actionName: 'Governed orchestration closed',
    eventKind: 'goal_execution.closed',
    actor: 'system',
    result: 'completed_without_change',
    createdAt: view.recordedAt ?? new Date().toISOString(),
    summary: 'The provider-free slice was independently reviewed, closed, and stopped without changing canonical state.',
  }, instanceId)
}

// ─────────────────────────────────────────────────────────────────────────────
// Infrastructure (stateport.infrastructure-local-libvirt/v1)
// ─────────────────────────────────────────────────────────────────────────────

const VM_STATE_MAP: Record<string, VMPowerState> = {
  not_defined: 'not_defined',
  stopped: 'stopped',
  shutoff: 'stopped',
  'shut off': 'stopped',
  // A paused or suspended guest is not executing; it is not "running healthy".
  paused: 'stopped',
  pmsuspended: 'stopped',
  starting: 'starting',
  running: 'running',
  // virsh "idle" is a running guest whose vCPUs are idle.
  idle: 'running',
  stopping: 'stopping',
  'in shutdown': 'stopping',
  crashed: 'unavailable',
  unavailable: 'unavailable',
  unknown: 'unavailable',
}

const HEALTH_STATE_MAP: Record<string, HealthState> = {
  not_checked: 'not_checked',
  checking: 'checking',
  healthy: 'healthy',
  passed: 'healthy',
  degraded: 'unhealthy',
  unhealthy: 'unhealthy',
  unreachable: 'unavailable',
  unavailable: 'unavailable',
}

const INFRA_OPERATIONS: readonly string[] = [
  'observe',
  'validate',
  'health_check',
  'create_or_update',
  'start',
  'stop',
  'restart',
  'destroy',
]

const infrastructureTargetIdentityWire = z.object({
  targetId: z.string().min(1),
  targetType: z.literal('local_libvirt'),
  displayName: z.string().min(1),
  domain: z.string().min(1),
  domainUuid: z.string().min(1),
  connection: z.literal('qemu:///session'),
  ssh: z.object({
    host: z.string().min(1),
    port: z.number().int().positive(),
    user: z.string().min(1),
  }),
})

const infraPlanWire = z.object({
  formatVersion: z.string().optional(),
  instanceId: z.string().min(1),
  target: infrastructureTargetIdentityWire,
  id: z.string().optional(),
  planId: z.string().optional(),
  operation: z.string().optional(),
  title: z.string().optional(),
  state: z.string().optional(),
  risk: z.string().optional(),
  requiresApproval: z.boolean().optional(),
  approvalRequired: z.boolean().optional(),
  coveredByAuthorization: z.boolean().optional(),
  coveredByGrant: z.boolean().optional(),
  authorization: z.object({ mode: z.string().optional(), grantId: z.string().optional() }).optional(),
  steps: z
    .array(
      z.object({
        id: z.string().optional(),
        title: z.string().optional(),
        detail: z.string().optional(),
        command: z.string().optional(),
        kind: z.string().optional(),
      }),
    )
    .optional(),
  commands: z.array(z.array(z.string())).optional(),
  digest: digestWire.optional(),
  planDigest: digestWire.optional(),
  beforeSummary: z.string().optional(),
  afterSummary: z.string().optional(),
  rollbackNotes: z.string().optional(),
  rollback: z.string().optional(),
  domainBefore: z.object({ state: z.string().optional() }).optional(),
  approvalId: z.string().optional(),
  receiptId: z.string().optional(),
  createdAt: isoTimestamp.optional(),
})

export function mapInfrastructurePlan(
  payload: unknown,
  expectedInstanceId: string,
  expectedTargetId?: string,
): InfrastructurePlan {
  const parsed = infraPlanWire.safeParse(payload)
  if (!parsed.success) {
    failClosed(
      'infrastructure plan did not match the current contract',
      parsed.error.issues.map((issue) => issue.path.join('.') || 'plan').join(', '),
    )
  }
  const wire = parsed.data
  if (wire.formatVersion !== 'stateport.infrastructure-plan/v1') {
    failClosed(
      `infrastructure plan formatVersion "${wire.formatVersion ?? 'missing'}"`,
      'expected stateport.infrastructure-plan/v1',
    )
  }
  if (wire.instanceId !== expectedInstanceId) {
    failClosed(
      `infrastructure plan instance identity "${wire.instanceId}"`,
      `expected ${expectedInstanceId}`,
    )
  }
  if (
    expectedTargetId !== undefined &&
    wire.target.targetId !== expectedTargetId
  ) {
    failClosed(
      `infrastructure plan target identity "${wire.target.targetId}"`,
      `expected ${expectedTargetId}`,
    )
  }
  const digest = wire.digest ?? wire.planDigest
  if (!digest) failClosed('infrastructure plan carries no digest')
  const id = wire.id ?? wire.planId ?? digest.value
  const backendOperation = wire.operation ?? 'observe'
  const operation = backendOperation === 'health' ? 'health_check' : backendOperation
  if (!INFRA_OPERATIONS.includes(operation)) failClosed(`infrastructure plan has unknown operation "${operation}"`)
  const state = wire.state ? LEGACY_RUN_STATE_MAP[wire.state] : undefined
  if (wire.state && !state) failClosed(`infrastructure plan ${id} reported unknown state "${wire.state ?? ''}"`)
  const requiresApproval = wire.requiresApproval ?? wire.approvalRequired ??
    !['observe', 'validate', 'health_check'].includes(operation)
  const coveredByAuthorization =
    wire.coveredByAuthorization ??
    wire.coveredByGrant ??
    wire.authorization?.mode === 'durable_grant'
  const steps: Array<{
    id?: string
    title?: string
    detail?: string
    command?: string
    kind?: string
  }> = wire.steps ??
    (wire.commands ?? []).map((command, index) => ({
      id: `command_${index + 1}`,
      title: `Command ${index + 1}`,
      command: command.join(' '),
      kind: 'command',
    }))
  const risk =
    wire.risk === 'medium' || wire.risk === 'high'
      ? wire.risk
      : operation === 'destroy'
        ? 'high'
        : ['start', 'stop', 'restart'].includes(operation)
          ? 'medium'
          : operation === 'create_or_update'
            ? 'medium'
          : 'low'
  return {
    id,
    instanceId: wire.instanceId,
    targetId: wire.target.targetId,
    operation: operation as InfrastructureOperation,
    title: wire.title ?? `${operation.replaceAll('_', ' ')} plan`,
    state: state ?? (requiresApproval && !coveredByAuthorization ? 'awaiting_approval' : 'prepared'),
    risk,
    requiresApproval,
    coveredByAuthorization,
    steps: steps.map((step, index) => ({
      id: step.id ?? `step_${index}`,
      title: step.title ?? `Step ${index + 1}`,
      detail: step.detail ?? step.command ?? '',
      kind: step.kind === 'check' || step.kind === 'gate' ? step.kind : 'command',
    })),
    digest,
    beforeSummary: wire.beforeSummary ?? `Target observed as ${wire.domainBefore?.state ?? 'not yet checked'}.`,
    afterSummary: wire.afterSummary ?? `Apply the exact ${operation.replaceAll('_', ' ')} plan, then validate the observed result.`,
    rollbackNotes: wire.rollbackNotes ?? wire.rollback ?? 'No rollback guidance was supplied by the service.',
    approvalId: wire.approvalId,
    receiptId: wire.receiptId,
    createdAt: wire.createdAt ?? new Date().toISOString(),
  }
}

const grantWire = z.object({
  formatVersion: z.string().optional(),
  instanceId: z.string().min(1),
  applicationId: z.literal('nixos-infrastructure'),
  target: infrastructureTargetIdentityWire,
  id: z.string().optional(),
  grantId: z.string().optional(),
  status: z.string().optional(),
  covers: z.array(z.string()).optional(),
  doesNotCover: z.array(z.string()).optional(),
  allowedOperations: z.array(z.string()).optional(),
  deniedOperations: z.array(z.string()).optional(),
  createdAt: isoTimestamp.optional(),
  expiresAt: isoTimestamp.optional(),
  proposalDigest: digestWire.optional(),
  createdByReceiptId: z.string().optional(),
  revokedAt: isoTimestamp.optional(),
  revokeReceiptId: z.string().optional(),
})

export interface GrantView {
  grant: AuthorizationGrant
  proposalDigest?: PlanDigest
}

export function mapGrant(
  payload: unknown,
  expectedInstanceId: string,
  expectedTargetId?: string,
): GrantView {
  const parsed = grantWire.safeParse(payload)
  if (!parsed.success) {
    failClosed(
      'authorization grant did not match the current contract',
      parsed.error.issues.map((issue) => issue.path.join('.') || 'grant').join(', '),
    )
  }
  const wire = parsed.data
  if (wire.formatVersion !== 'stateport.infrastructure-daily-driver-grant/v1') {
    failClosed(
      `authorization grant formatVersion "${wire.formatVersion ?? 'missing'}"`,
      'expected stateport.infrastructure-daily-driver-grant/v1',
    )
  }
  if (wire.instanceId !== expectedInstanceId) {
    failClosed(
      `authorization grant instance identity "${wire.instanceId}"`,
      `expected ${expectedInstanceId}`,
    )
  }
  if (
    expectedTargetId !== undefined &&
    wire.target.targetId !== expectedTargetId
  ) {
    failClosed(
      `authorization grant target identity "${wire.target.targetId}"`,
      `expected ${expectedTargetId}`,
    )
  }
  const id = wire.id ?? wire.grantId
  if (!id) failClosed('authorization grant without identity')
  const statusMap: Record<string, AuthorizationGrant['status']> = {
    proposed: 'proposed',
    active: 'active',
    expired: 'expired',
    revoked: 'revoked',
  }
  const status = statusMap[wire.status ?? 'proposed']
  if (!status) failClosed(`authorization grant ${id} reported unknown status "${wire.status ?? ''}"`)
  const operationMap: Record<string, InfrastructureOperation | undefined> = {
    'repository.inspect': 'observe',
    'vm.observe': 'observe',
    'vm.health.read': 'health_check',
    'vm.start': 'start',
    'vm.stop.graceful': 'stop',
    'vm.restart': 'restart',
    observe: 'observe',
    validate: 'validate',
    health: 'health_check',
    health_check: 'health_check',
    start: 'start',
    stop: 'stop',
    restart: 'restart',
    destroy: 'destroy',
  }
  const covers = [...new Set((wire.covers ?? wire.allowedOperations ?? []).map((operation) => operationMap[operation]).filter(
    (operation): operation is InfrastructureOperation => operation !== undefined,
  ))]
  return {
    grant: {
      id,
      instanceId: wire.instanceId,
      targetId: wire.target.targetId,
      status,
      covers,
      doesNotCover: wire.doesNotCover ?? wire.deniedOperations ?? [],
      createdAt: wire.createdAt ?? new Date().toISOString(),
      expiresAt: wire.expiresAt,
      createdByReceiptId: wire.createdByReceiptId,
      revokedAt: wire.revokedAt,
      revokeReceiptId: wire.revokeReceiptId,
    },
    proposalDigest: wire.proposalDigest,
  }
}

const infrastructureWire = z.object({
  formatVersion: z.string().optional(),
  instanceId: z.string().min(1),
  repository: repositoryWire.optional(),
  target: infrastructureTargetIdentityWire,
  domain: z
    .object({
      state: z.string().optional(),
      availability: z.string().optional(),
      error: z.string().nullable().optional(),
      since: isoTimestamp.optional(),
      ssh: z.object({
        status: z.string().optional(),
        reason: z.string().optional(),
        available: z.boolean().optional(),
      }).optional(),
    })
    .optional(),
  vm: z.object({ state: z.string().optional(), since: isoTimestamp.optional() }).optional(),
  ssh: z.object({ state: z.string().optional(), detail: z.string().optional() }).optional(),
  health: z.object({
    state: z.string().optional(),
    status: z.string().optional(),
    reason: z.string().optional(),
    checkedAt: isoTimestamp.optional(),
    detail: z.string().optional(),
  }).optional(),
  grant: z.unknown().optional(),
  dailyDriverGrant: z.unknown().optional(),
  authorization: z.unknown().optional(),
  plan: z.unknown().optional(),
  lastRun: z.object({
    operation: z.string().optional(),
    endedAt: isoTimestamp.optional(),
    receipt: z.object({ createdAt: isoTimestamp.optional() }).passthrough().optional(),
    result: z.object({
      health: z.object({
        state: z.string().optional(),
        status: z.string().optional(),
        reason: z.string().optional(),
        checkedAt: isoTimestamp.optional(),
        detail: z.string().optional(),
      }).optional(),
    }).passthrough().optional(),
  }).passthrough().nullable().optional(),
})

export interface InfrastructureView {
  target: InfrastructureTarget
  grant: GrantView | null
  plan: InfrastructurePlan | null
}

export function mapInfrastructure(payload: unknown, instanceId: string): InfrastructureView {
  const parsed = infrastructureWire.safeParse(payload)
  if (!parsed.success) {
    failClosed(
      'infrastructure response did not match the current contract',
      parsed.error.issues.map((issue) => issue.path.join('.') || 'projection').join(', '),
    )
  }
  const wire = parsed.data
  if (wire.formatVersion !== FORMAT.infrastructureLocalLibvirt) {
    failClosed(
      `infrastructure formatVersion "${wire.formatVersion ?? 'missing'}"`,
      `expected ${FORMAT.infrastructureLocalLibvirt}`,
    )
  }
  if (wire.instanceId !== instanceId) {
    failClosed(
      `infrastructure instance identity "${wire.instanceId}"`,
      `expected ${instanceId}`,
    )
  }
  const targetId = wire.target.targetId
  const domainState = wire.domain?.state ?? wire.vm?.state ?? 'unknown'
  const vmState = VM_STATE_MAP[domainState]
  if (!vmState) failClosed(`infrastructure domain reported unknown state "${domainState}"`)
  const sshRaw = wire.ssh?.state ?? wire.domain?.ssh?.status ?? 'not_checked'
  const sshState =
    vmState === 'not_defined'
      ? 'unavailable_vm_not_defined'
      : vmState === 'stopped'
      ? 'unavailable_vm_stopped'
      : sshRaw === 'ssh_ready'
        ? 'ready'
        : ['not_checked', 'ssh_key_not_enrolled', 'ssh_not_configured'].includes(sshRaw)
          ? 'not_checked'
          : 'failed'
  const healthWire = wire.health ?? wire.lastRun?.result?.health
  const healthRaw = healthWire?.state ?? healthWire?.status ?? 'not_checked'
  const healthState = HEALTH_STATE_MAP[healthRaw]
  if (!healthState) failClosed(`infrastructure health reported unknown state "${healthRaw}"`)
  const domainAvailable = wire.domain?.availability
  const targetAvailable =
    domainAvailable ? domainAvailable === 'available' : vmState !== 'unavailable'
  const target: InfrastructureTarget = {
    id: targetId,
    instanceId: wire.instanceId,
    name: wire.target.displayName,
    kind: 'local_vm',
    available: targetAvailable,
    unavailableReason: targetAvailable
      ? undefined
      : wire.domain?.error ?? 'The infrastructure target could not be observed.',
    repository: mapRepository(wire.repository) ?? { name: 'repository', branch: 'main', revision: '', clean: true },
    vm: { state: vmState, since: wire.domain?.since ?? wire.vm?.since },
    ssh: {
      state: sshState,
      detail: wire.ssh?.detail ?? wire.domain?.ssh?.reason ?? wire.domain?.ssh?.status,
    },
    health: {
      state: healthState,
      checkedAt: healthWire
        ? healthWire.checkedAt ?? wire.lastRun?.endedAt ?? wire.lastRun?.receipt?.createdAt
        : undefined,
      detail: healthWire?.detail ?? healthWire?.reason,
    },
  }
  const grantSource = wire.grant ?? wire.authorization ?? wire.dailyDriverGrant
  const grant = grantSource !== undefined && grantSource !== null ? mapGrant(grantSource, wire.instanceId, targetId) : null
  const plan = wire.plan !== undefined && wire.plan !== null ? mapInfrastructurePlan(wire.plan, wire.instanceId, targetId) : null
  return { target, grant, plan }
}

// ─────────────────────────────────────────────────────────────────────────────
// Terminal ticket (stateport.terminal-socket/v1)
// ─────────────────────────────────────────────────────────────────────────────

const terminalTicketWire = z
  .object({
    formatVersion: z.string(),
    socketPath: z.string(),
    subprotocol: z.string(),
    sessionId: z.string(),
    oneUseToken: z.string().min(1),
    purpose: z.enum(['create', 'reconnect']),
    expiresAt: isoTimestamp,
    target: z
      .object({
        targetClass: z.string().min(1),
      })
      .passthrough(),
  })
  .strict()

export interface TerminalTicket {
  formatVersion: typeof TERMINAL_TICKET_FORMAT
  socketPath: string
  subprotocol: typeof TERMINAL_SUBPROTOCOL
  sessionId: string
  oneUseToken: string
  purpose: string
  targetClass: string
}

export function mapTerminalTicket(payload: unknown): TerminalTicket {
  const parsed = terminalTicketWire.safeParse(payload)
  if (!parsed.success) {
    failClosed(
      'terminal ticket did not match the exact service contract',
      parsed.error.issues.map((issue) => issue.path.join('.') || 'ticket').join(', '),
    )
  }
  const wire = parsed.data
  if (wire.formatVersion !== TERMINAL_TICKET_FORMAT) {
    failClosed(`terminal ticket formatVersion "${wire.formatVersion}"`, `expected ${TERMINAL_TICKET_FORMAT}`)
  }
  if (wire.subprotocol !== TERMINAL_SUBPROTOCOL) {
    failClosed(`terminal ticket subprotocol "${wire.subprotocol}"`, `expected ${TERMINAL_SUBPROTOCOL}`)
  }
  if (wire.socketPath !== endpoints.terminalSocket) {
    failClosed(
      `terminal ticket socketPath "${wire.socketPath}"`,
      `expected ${endpoints.terminalSocket}`,
    )
  }
  return {
    formatVersion: TERMINAL_TICKET_FORMAT,
    socketPath: wire.socketPath,
    subprotocol: TERMINAL_SUBPROTOCOL,
    sessionId: wire.sessionId,
    oneUseToken: wire.oneUseToken,
    purpose: wire.purpose,
    targetClass: wire.target.targetClass,
  }
}

/** Terminal targets are derived from the experience descriptor (§16). */
export function terminalTargetsFromCapabilities(instanceId: string, capabilities: CapabilityState[]): TerminalTarget[] {
  const terminal = capabilities.find((c) => c.id === 'terminal')
  if (!terminal || terminal.status === 'unavailable') return []
  const available = terminal.status === 'available'
  return [
    {
      id: `tgt_${instanceId}_pty`,
      instanceId,
      label: 'Local PTY',
      kind: 'local_pty',
      available,
      unavailableReason: available
        ? undefined
        : (terminal.reason ??
          (terminal.status === 'environment_gated'
            ? 'The terminal is gated by the current environment.'
            : 'The terminal is degraded on this instance.')),
    },
  ]
}

/** Attention is the backend-owned notification lifecycle; receipts are history. */
export function notificationsFromAttention(attention: AttentionItem[]): NotificationItem[] {
  return attention.map((item) => ({
    id: item.id,
    instanceId: item.instanceId,
    title: item.title,
    body: item.detail,
    importance:
      item.severity === 'urgent' || item.severity === 'action_needed'
        ? 'important'
        : 'normal',
    createdAt: item.createdAt,
    read: item.read || item.acknowledged,
    acknowledged: item.acknowledged,
    route: item.actionRoute,
  }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Repository import
// ─────────────────────────────────────────────────────────────────────────────

export function mapRepositoryCandidates(payload: unknown): RepositoryCandidate[] {
  return indexPayload(payload, ['candidates', 'items']).map((entry) => {
    if (!isRecord(entry) || typeof entry.candidateId !== 'string') failClosed('repository candidate without an identity')
    return {
      candidateId: entry.candidateId,
      displayName: typeof entry.displayName === 'string' ? entry.displayName : entry.candidateId,
      relativeLocation: typeof entry.relativeLocation === 'string' ? entry.relativeLocation : '',
      suggestedPackageId: typeof entry.suggestedPackageId === 'string' ? entry.suggestedPackageId : undefined,
    }
  })
}

export function mapRepositoryInspection(payload: unknown): RepositoryInspection {
  if (!isRecord(payload)) failClosed('inspection result was not an object')
  if (typeof payload.inspectionDigest !== 'string' || !payload.inspectionDigest) {
    failClosed('inspection result carried no digest')
  }
  const identity = isRecord(payload.sourceIdentity) ? payload.sourceIdentity : {}
  const findings: RepositoryInspection['findings'] = []
  if (Array.isArray(payload.safetyFindings)) {
    for (const finding of payload.safetyFindings) {
      if (!isRecord(finding) || typeof finding.message !== 'string') continue
      findings.push({
        code: typeof finding.code === 'string' ? finding.code : 'finding',
        severity: finding.severity === 'error' ? 'error' : 'warning',
        message: finding.message,
      })
    }
  }
  return {
    candidateId: typeof payload.candidateId === 'string' ? payload.candidateId : undefined,
    source: typeof payload.source === 'string' ? payload.source : '',
    inspectionDigest: payload.inspectionDigest,
    branch: typeof identity.branch === 'string' ? identity.branch : 'HEAD',
    headCommit: typeof identity.headCommit === 'string' ? identity.headCommit : '',
    dirty: identity.dirty === true,
    stateSpec: payload.stateSpec,
    findings,
    mutated: typeof payload.mutated === 'boolean' ? payload.mutated : undefined,
  }
}

export function mapRepositoryRegistration(
  payload: unknown,
  expected?: {
    candidateId: string
    inspectionDigest: string
    instanceId: string
  },
): RepositoryRegistration {
  if (!isRecord(payload)) failClosed('registration result was not an object')
  const entry = isRecord(payload.entry) ? payload.entry : payload
  const instanceId = entry.instanceId ?? entry.id
  if (typeof instanceId !== 'string' || !instanceId) failClosed('registration result carried no instance identity')
  const receipt = isRecord(payload.receipt) ? payload.receipt : undefined
  if (expected) {
    if (instanceId !== expected.instanceId) {
      failClosed(
        `repository registration instance identity "${instanceId}"`,
        `expected ${expected.instanceId}`,
      )
    }

    const inspection = isRecord(payload.inspection) ? payload.inspection : undefined
    if (inspection?.candidateId !== expected.candidateId) {
      failClosed(
        `repository registration inspection candidate "${String(inspection?.candidateId ?? 'missing')}"`,
        `expected ${expected.candidateId}`,
      )
    }
    if (inspection.inspectionDigest !== expected.inspectionDigest) {
      failClosed(
        `repository registration inspection digest "${String(inspection.inspectionDigest ?? 'missing')}"`,
        `expected ${expected.inspectionDigest}`,
      )
    }

    const approval = isRecord(receipt?.approval) ? receipt.approval : undefined
    if (approval?.proposalDigest !== expected.inspectionDigest) {
      failClosed(
        `repository registration approval digest "${String(approval?.proposalDigest ?? 'missing')}"`,
        `expected ${expected.inspectionDigest}`,
      )
    }

    // The current receipt carries both bindings. Keep the checks conditional
    // so an otherwise valid response that intentionally omits duplicated
    // receipt metadata is not reinterpreted, while any supplied identity is
    // still authoritative and must match exactly.
    if (receipt?.instanceId !== undefined && receipt.instanceId !== expected.instanceId) {
      failClosed(
        `repository registration receipt instance identity "${String(receipt.instanceId)}"`,
        `expected ${expected.instanceId}`,
      )
    }
    if (
      receipt?.inspectionDigest !== undefined &&
      receipt.inspectionDigest !== expected.inspectionDigest
    ) {
      failClosed(
        `repository registration receipt inspection digest "${String(receipt.inspectionDigest)}"`,
        `expected ${expected.inspectionDigest}`,
      )
    }
  }
  return {
    instanceId,
    conversationId: typeof payload.conversationId === 'string' ? payload.conversationId : undefined,
    receiptId: typeof receipt?.receiptId === 'string' ? receipt.receiptId : undefined,
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Install receipt (stateport.application-install-receipt/v1)
// ─────────────────────────────────────────────────────────────────────────────

const installReceiptWire = z.object({
  entry: z.object({
    applicationId: z.string().min(1),
    instanceId: z.string().min(1),
    status: z.literal('active'),
  }),
  receipt: z
    .object({
      formatVersion: z.literal(FORMAT.applicationInstallReceipt),
      receiptId: z.string().regex(/^application-install\.[A-Za-z0-9._-]+\.[0-9a-f]{12}$/),
      receiptDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    })
    .strict(),
})

export interface InstallReceiptReference {
  applicationId: string
  instanceId: string
  receiptId: string
  receiptDigest: PlanDigest
}

export function mapInstallReceipt(
  payload: unknown,
  expected?: { applicationId: string; instanceId: string },
): InstallReceiptReference {
  const parsed = installReceiptWire.safeParse(payload)
  if (!parsed.success) {
    failClosed(
      'application install result did not match the current receipt contract',
      parsed.error.issues.map((issue) => issue.path.join('.') || 'result').join(', '),
    )
  }
  const wire = parsed.data
  if (expected && wire.entry.applicationId !== expected.applicationId) {
    failClosed(
      `application install identity "${wire.entry.applicationId}"`,
      `expected ${expected.applicationId}`,
    )
  }
  if (expected && wire.entry.instanceId !== expected.instanceId) {
    failClosed(
      `application installation instance identity "${wire.entry.instanceId}"`,
      `expected ${expected.instanceId}`,
    )
  }
  const expectedReceiptPrefix = `application-install.${wire.entry.instanceId}.`
  if (!wire.receipt.receiptId.startsWith(expectedReceiptPrefix)) {
    failClosed(
      `application install receipt identity "${wire.receipt.receiptId}"`,
      `expected an identity bound to ${wire.entry.instanceId}`,
    )
  }
  return {
    applicationId: wire.entry.applicationId,
    instanceId: wire.entry.instanceId,
    receiptId: wire.receipt.receiptId,
    receiptDigest: {
      algorithm: 'sha256',
      value: wire.receipt.receiptDigest,
    },
  }
}
