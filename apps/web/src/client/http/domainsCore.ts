/**
 * HTTP domain clients — core surfaces (session, applications, catalog,
 * repository import, settings, activity, receipts, files seam, recovery,
 * operations, scenario).
 *
 * Every client talks to the real same-origin service through HttpTransport.
 * Failures surface as honest ClientErrors — NEVER as mock/fallback data.
 * Where the backend contract has no endpoint for an existing interface
 * method, the method throws ClientError 'unavailable' with a documented
 * reason (see INTEGRATION_MANIFEST.md).
 */
import { z } from 'zod'

import type {
  ActivityClient,
  ApplicationsClient,
  AppSettingsClient,
  CatalogClient,
  DeepPartial,
  FilesClient,
  GlobalSettingsClient,
  OperationsClient,
  ReceiptsClient,
  RecoveryClient,
  RepositoryImportClient,
  ScenarioClient,
  SessionClient,
  SettingsRollbackInput,
} from '../client'
import { schemas } from '../schemas'
import { assertSettingsImportSize } from '../settingsImportPolicy'
import type {
  ActivityItem,
  ApplicationInstance,
  AppSettings,
  AttentionItem,
  BuildInfo,
  CatalogPackage,
  CreateFileResult,
  DeleteFileResult,
  FileDiff,
  FileEntry,
  FileMutationFailure,
  FileNode,
  GlobalSettings,
  GlobalSettingsRollbackHistory,
  GlobalSettingsRollbackTarget,
  LocalServiceStatus,
  NotificationItem,
  OperationRecord,
  Receipt,
  RecoveryStatus,
  RepositoryInspection,
  RenameFileResult,
  RestoreApproval,
  RestorePlan,
  RestoreReceipt,
  SessionInfo,
} from '../types'
import { ClientError } from '../types'
import { defaultAppSettings, defaultGlobalSettings } from '../mock/seed'
import { endpoints } from './endpoints'
import {
  mapActivityProjection,
  mapAttentionItem,
  mapCatalog,
  mapExperience,
  mapGlobalSettings,
  mapGoalExecutionReceipt,
  mapAppSettings,
  mapInstallReceipt,
  mapInstance,
  mapInstanceIndex,
  mapPackage,
  mapReceipt,
  mapReceiptIndex,
  mapRepositoryCandidates,
  mapRepositoryInspection,
  mapRepositoryRegistration,
  mapSession,
  mapStatus,
  notificationsFromAttention,
  type ExperienceView,
} from './mappers'
import { HttpTransport, voidSchema } from './transport'

const unknownPayload = z.unknown()
const restoreDigest = z.string().regex(/^sha256:[0-9a-f]{64}$/)
const restoreId = z.string().regex(/^[a-z][a-z0-9-]{1,63}$/)
const restorePlannedSourceAccess = z.union([
  z.object({ disposition: z.literal('not_propagated') }).strict(),
  z
    .object({
      disposition: z.literal('propagate_exact_receipt'),
      sourceAccessClass: z.literal('canonical_release'),
      productionInstallAllowed: z.literal(true),
      sourceReceiptDigest: restoreDigest,
    })
    .strict(),
  z
    .object({
      disposition: z.literal('propagate_exact_receipt'),
      sourceAccessClass: z.literal('development_candidate'),
      productionInstallAllowed: z.literal(false),
      sourceReceiptDigest: restoreDigest,
    })
    .strict(),
])
const restoreReceiptSourceAccess = z.union([
  z.object({ disposition: z.literal('not_propagated') }).strict(),
  z
    .object({
      disposition: z.literal('propagated'),
      sourceAccessClass: z.literal('canonical_release'),
      productionInstallAllowed: z.literal(true),
      sourceReceiptDigest: restoreDigest,
      destinationReceiptDigest: restoreDigest,
    })
    .strict(),
  z
    .object({
      disposition: z.literal('propagated'),
      sourceAccessClass: z.literal('development_candidate'),
      productionInstallAllowed: z.literal(false),
      sourceReceiptDigest: restoreDigest,
      destinationReceiptDigest: restoreDigest,
    })
    .strict(),
])
const restoreBackup = z
  .object({
    receiptId: z.string().regex(/^backup-[0-9a-f]{24}$/),
    receiptDigest: restoreDigest,
    createdAt: z.string().min(20),
    archiveDigest: restoreDigest,
    archiveFileDigest: restoreDigest,
    manifestDigest: restoreDigest,
    sourceLockDigest: restoreDigest,
    fileCount: z.number().int().positive(),
    storageLocation: z.literal('stateport_managed_backup_root'),
  })
  .strict()
const restorePlanWire = z
  .object({
    formatVersion: z.literal('stateport.restore-plan/v1'),
    operation: z.literal('restore_new_instance'),
    sourceInstanceId: restoreId,
    destinationInstanceId: restoreId,
    destinationName: z.string().min(1).max(120),
    identityPolicy: z.literal('reidentify'),
    backup: restoreBackup,
    preconditions: z
      .object({
        sourceBindingDigest: restoreDigest,
        destinationRootClass: z.literal('stateport_managed_instances_root'),
        destinationAbsent: z.literal(true),
        destinationCatalogIdentityAbsent: z.literal(true),
      })
      .strict(),
    dryRun: z
      .object({
        status: z.literal('verified'),
        instanceId: restoreId,
        fileCount: z.number().int().positive(),
        archiveDigest: restoreDigest,
      })
      .strict(),
    effects: z
      .object({
        sourceCanonicalState: z.literal('unchanged'),
        destinationCanonicalState: z.literal('new_instance_created'),
        externalEffectsRestored: z.literal(false),
        overwriteAllowed: z.literal(false),
        sourceAccess: restorePlannedSourceAccess,
      })
      .strict(),
    limitations: z.array(z.string().min(1)).min(3),
    createdAt: z.string().min(20),
    expiresAt: z.string().min(20),
    planDigest: restoreDigest,
  })
  .strict()
const restoreApprovalWire = z
  .object({
    formatVersion: z.literal('stateport.restore-approval/v1'),
    operation: z.literal('restore_new_instance'),
    sourceInstanceId: restoreId,
    destinationInstanceId: restoreId,
    planDigest: restoreDigest,
    actor: z
      .object({
        actorId: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/),
        actorRole: z.enum(['platform_operator', 'local_operator']),
      })
      .strict(),
    decision: z.literal('approved'),
    approvedAt: z.string().min(20),
    expiresAt: z.string().min(20),
    approvalDigest: restoreDigest,
  })
  .strict()
const restoreReceiptWire = z
  .object({
    formatVersion: z.literal('stateport.restore-receipt/v1'),
    receiptId: z.string().regex(/^restore-[0-9a-f]{24}$/),
    operation: z.literal('restore_new_instance'),
    status: z.literal('validated'),
    sourceInstanceId: restoreId,
    destinationInstanceId: restoreId,
    planDigest: restoreDigest,
    approvalDigest: restoreDigest,
    backup: restoreBackup,
    result: z
      .object({
        identityPolicy: z.literal('reidentify'),
        instanceId: restoreId,
        fileCount: z.number().int().positive(),
        archiveDigest: restoreDigest,
        baseGit: z.string().regex(/^[0-9a-f]{40,64}$/),
        validation: z.object({ valid: z.literal(true), issues: z.tuple([]) }).strict(),
        catalogIdentity: z.record(z.string(), z.unknown()),
      })
      .strict(),
    effects: z
      .object({
        sourceCanonicalState: z.literal('unchanged'),
        destinationCanonicalState: z.literal('new_instance_created'),
        externalEffectsRestored: z.literal(false),
        sourceAccess: restoreReceiptSourceAccess,
      })
      .strict(),
    createdAt: z.string().min(20),
    receiptDigest: restoreDigest,
  })
  .strict()
const recoveryStatusWire = z
  .object({
    formatVersion: z.literal('stateport.recovery-status/v1'),
    sourceInstanceId: restoreId,
    status: z.enum(['no_backup', 'verified', 'degraded']),
    latest: z
      .object({
        instanceId: restoreId,
        archiveDigest: restoreDigest,
        archiveFileDigest: restoreDigest,
        createdAt: z.string().min(20),
        validation: z.literal('verified'),
        backupReceipt: z.object({ receiptId: z.string() }).passthrough(),
        storageLocation: z.literal('stateport_managed_backup_root'),
      })
      .passthrough()
      .nullable(),
    operatorInspectionRequired: z.boolean().optional(),
    verificationIssues: z.array(z.string()).optional(),
    verification: z.record(z.string(), z.unknown()).optional(),
    restore: z
      .object({
        status: z.enum(['not_planned', 'planned', 'approved', 'validated', 'failed']),
        latestPlanDigest: restoreDigest.nullable(),
        latestApprovalDigest: restoreDigest.nullable(),
        latestReceiptId: z.string().nullable(),
        operatorInspectionRequired: z.boolean(),
        stagingRetained: z.boolean().optional(),
        destinationInstanceId: restoreId.optional(),
        expiresAt: z.string().optional(),
        failureReasonCode: z.string().optional(),
      })
      .strict(),
    limitations: z
      .object({
        filesystemStateOnly: z.literal(true),
        externalEffectsRestored: z.literal(false),
        overwriteRestoreSupported: z.literal(false),
      })
      .strict(),
  })
  .strict()

function unavailable(what: string, detail: string): ClientError {
  return new ClientError('unavailable', what, { detail })
}

// ─────────────────────────────────────────────────────────────────────────────
// Local UI overlay (frontend-owned workspace state — Level B).
//
// Pinned applications, last-opened timestamps, and notification snoozes are
// user-local presentation state with no backend endpoint. They live in
// localStorage — this is REAL user state (like layout preferences), never
// mock data.
// ─────────────────────────────────────────────────────────────────────────────

interface UiOverlay {
  pinned: Record<string, boolean>
  lastOpened: Record<string, string>
  snoozed: Record<string, string>
}

const OVERLAY_KEY = 'stateport.http.ui-overlay.v1'

class OverlayStore {
  // Always read-through (never cached): multiple domain clients hold their
  // own OverlayStore instance and localStorage is the shared source of truth.
  private load(): UiOverlay {
    let parsed: UiOverlay = { pinned: {}, lastOpened: {}, snoozed: {} }
    try {
      const raw = typeof localStorage !== 'undefined' ? localStorage.getItem(OVERLAY_KEY) : null
      if (raw) {
        const candidate = JSON.parse(raw) as Partial<UiOverlay>
        parsed = {
          pinned: candidate.pinned ?? {},
          lastOpened: candidate.lastOpened ?? {},
          snoozed: candidate.snoozed ?? {},
        }
      }
    } catch {
      // Corrupt overlay → start clean (presentation state only).
    }
    return parsed
  }

  private save(state: UiOverlay): void {
    try {
      if (typeof localStorage !== 'undefined') localStorage.setItem(OVERLAY_KEY, JSON.stringify(state))
    } catch {
      // Storage full/blocked — overlay stays unchanged for this session.
    }
  }

  getPinned(instanceId: string): boolean | undefined {
    return this.load().pinned[instanceId]
  }

  setPinned(instanceId: string, pinned: boolean): void {
    const state = this.load()
    state.pinned[instanceId] = pinned
    this.save(state)
  }

  getLastOpened(instanceId: string): string | undefined {
    return this.load().lastOpened[instanceId]
  }

  touch(instanceId: string): void {
    const state = this.load()
    state.lastOpened[instanceId] = new Date().toISOString()
    this.save(state)
  }

  getSnoozed(notificationId: string): string | undefined {
    return this.load().snoozed[notificationId]
  }

  snooze(notificationId: string, until: string): void {
    const state = this.load()
    state.snoozed[notificationId] = until
    this.save(state)
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Session
// ─────────────────────────────────────────────────────────────────────────────

export class HttpSessionClient implements SessionClient {
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async getSession(): Promise<SessionInfo> {
    const payload = await this.transport.request(endpoints.session, { schema: unknownPayload })
    return mapSession(payload)
  }

  async getLocalServiceStatus(): Promise<LocalServiceStatus> {
    const payload = await this.transport.request(endpoints.status, { schema: unknownPayload })
    return mapStatus(payload, endpoints.status)
  }

  /**
   * There is no build-info endpoint in the contract; the report is derived
   * honestly from the service status (version) and this bundle's boot time.
   */
  async getBuildInfo(): Promise<BuildInfo> {
    let version = 'unknown'
    try {
      const status = await this.getLocalServiceStatus()
      version = status.version ?? 'unknown'
    } catch {
      // The status call failing is reported by the service chip separately.
    }
    return {
      version: version === 'unknown' ? __BUILD_VERSION__ : version,
      commit: `${__BUILD_SHORT__}${__BUILD_DIRTY__ ? '+dirty' : ''}`,
      builtAt: __BUILD_TIME__,
      adapter: 'http',
      mode: import.meta.env.DEV ? 'development' : 'production',
    }
  }

  async reconnect(): Promise<LocalServiceStatus> {
    // Force a fresh session prime (CSRF), then re-read status honestly.
    this.transport.invalidateSession()
    await this.transport.ensureSession()
    return this.getLocalServiceStatus()
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Applications (+ per-instance experience capabilities)
// ─────────────────────────────────────────────────────────────────────────────

export class HttpApplicationsClient implements ApplicationsClient {
  readonly canRename = false
  private readonly overlay = new OverlayStore()
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  /**
   * Resolve the backend-owned experience authority.
   *
   * An explicit `experience_unavailable` response is a safe, routeless
   * projection. Transport failures, malformed descriptors, and identity
   * mismatches propagate: they must not silently activate legacy
   * capability-only navigation.
   */
  private async experienceFor(instanceId: string): Promise<{
    view?: ExperienceView
    resolution: 'resolved' | 'unavailable'
  }> {
    try {
      const payload = await this.transport.request(endpoints.instanceExperience(instanceId), {
        schema: unknownPayload,
      })
      return { view: mapExperience(payload, instanceId), resolution: 'resolved' }
    } catch (error) {
      if (
        error instanceof ClientError &&
        error.status === 404 &&
        error.code === 'experience_unavailable'
      ) {
        return { resolution: 'unavailable' }
      }
      throw error
    }
  }

  private withOverlay(instance: ApplicationInstance): ApplicationInstance {
    return {
      ...instance,
      pinned: this.overlay.getPinned(instance.id) ?? instance.pinned,
      lastOpenedAt: this.overlay.getLastOpened(instance.id) ?? instance.lastOpenedAt,
    }
  }

  async list(): Promise<ApplicationInstance[]> {
    const payload = await this.transport.request(endpoints.instances, { schema: unknownPayload })
    const entries = mapInstanceIndex(payload)
    const details = await Promise.all(entries.map(async (entry) => {
      const record = entry as { id?: unknown; instanceId?: unknown }
      const id = typeof record.id === 'string' ? record.id : record.instanceId
      if (typeof id !== 'string') {
        throw new ClientError(
          'validation',
          'The application index carried an entry without instance identity',
        )
      }
      const [detail, experience] = await Promise.all([
        this.transport.request(endpoints.instance(id), { schema: unknownPayload }).catch(() => entry),
        this.experienceFor(id),
      ])
      return { detail, experience }
    }))
    return entries.map((entry, index) =>
      this.withOverlay(mapInstance(details[index].detail, {
        experience: details[index].experience.view,
        experienceResolution: details[index].experience.resolution,
        index: entry as Record<string, unknown>,
      })),
    )
  }

  async get(instanceId: string): Promise<ApplicationInstance> {
    const [payload, experience, indexPayload] = await Promise.all([
      this.transport.request(endpoints.instance(instanceId), { schema: unknownPayload }),
      this.experienceFor(instanceId),
      this.transport.request(endpoints.instances, { schema: unknownPayload }),
    ])
    const index = mapInstanceIndex(indexPayload).find((entry) => {
      const record = entry as { id?: unknown; instanceId?: unknown }
      return record.id === instanceId || record.instanceId === instanceId
    })
    return this.withOverlay(mapInstance(payload, {
      experience: experience.view,
      experienceResolution: experience.resolution,
      index: index as Record<string, unknown> | undefined,
    }))
  }

  /**
   * The contract has no instance-rename endpoint (the user-owned name is set
   * at fixture-install time). Fail closed instead of inventing one.
   */
  rename(): Promise<ApplicationInstance> {
    return Promise.reject(
      unavailable(
        'Renaming an application is not supported by the connected service',
        'The backend contract has no instance rename endpoint; the name is fixed at install time.',
      ),
    )
  }

  async setPinned(instanceId: string, pinned: boolean): Promise<ApplicationInstance> {
    this.overlay.setPinned(instanceId, pinned)
    return this.get(instanceId)
  }

  async touchOpened(instanceId: string): Promise<void> {
    this.overlay.touch(instanceId)
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Catalog (+ identity-bound fixture installation)
// ─────────────────────────────────────────────────────────────────────────────

function newInstanceId(): string {
  const bytes = new Uint8Array(8)
  crypto.getRandomValues(bytes)
  return `ins_${[...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')}`
}

/**
 * External-repository catalog identities use the backend's hyphen-only ID
 * grammar and are derived deterministically from the exact approved
 * inspection digest. A retry after a lost/ambiguous register response
 * re-sends the SAME instanceId, so the backend idempotency path (same
 * instanceId + same resolved path) returns the existing registration instead
 * of raising a duplicate-instance error. Different inspections — and therefore
 * genuinely different registrations — always derive different identities.
 */
async function externalInstanceIdForInspection(inspectionDigest: string): Promise<string> {
  if (!crypto.subtle) {
    throw new ClientError(
      'unavailable',
      'This browser context cannot derive a deterministic instance identity',
      { detail: 'Repository registration requires WebCrypto SHA-256 (secure context).' },
    )
  }
  const canonical = `stateport:external-instance:${inspectionDigest}`
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  const hex = [...new Uint8Array(digest)].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('')
  return `ins-${hex}`
}

async function managedTemplateInstanceIdForInspection(inspectionDigest: string): Promise<string> {
  if (!crypto.subtle) {
    throw new ClientError(
      'unavailable',
      'This browser context cannot derive a deterministic template identity',
      { detail: 'Template import requires WebCrypto SHA-256 (secure context).' },
    )
  }
  const canonical = `stateport:managed-template:${inspectionDigest}`
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  const hex = [...new Uint8Array(digest)].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('')
  return `template-${hex}`
}

export class HttpCatalogClient implements CatalogClient {
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async list(): Promise<CatalogPackage[]> {
    // Installed counts are derived from the instances index. If that index
    // cannot be loaded, the list fails honestly with the transport error —
    // silently presenting degraded or zero counts as truth is not acceptable
    // (consumers such as CatalogPage render explicit error/stale states).
    const [packagesPayload, instancesPayload] = await Promise.all([
      this.transport.request(endpoints.applications, { schema: unknownPayload }),
      this.transport.request(endpoints.instances, { schema: unknownPayload }),
    ])
    const catalog = mapCatalog(packagesPayload)
    // Derive installed counts from the instances index when the catalog
    // payload does not carry them (Level B derivation over real data).
    try {
      const counts = new Map<string, number>()
      for (const entry of mapInstanceIndex(instancesPayload)) {
        const record = entry as { applicationId?: unknown; packageId?: unknown }
        const key = typeof record.applicationId === 'string' ? record.applicationId : typeof record.packageId === 'string' ? record.packageId : undefined
        if (key) counts.set(key, (counts.get(key) ?? 0) + 1)
      }
      for (const item of catalog) item.installedInstanceCount = counts.get(item.pkg.id) ?? item.installedInstanceCount
    } catch {
      // Instances index shape unexpected — keep catalog-reported counts.
    }
    return catalog
  }

  async get(packageId: string) {
    const catalog = await this.list()
    const found = catalog.find((item) => item.pkg.id === packageId)
    if (!found) throw new ClientError('http', `Package not found: ${packageId}`, { status: 404 })
    return found
  }

  async createInstance(packageId: string, input: { name: string }) {
    // Identity-bound installation: the descriptor digests must come from the
    // service — they are never invented client-side.
    const packagesPayload = await this.transport.request(endpoints.applications, { schema: unknownPayload })
    const entries = Array.isArray(packagesPayload)
      ? packagesPayload
      : ((packagesPayload as { applications?: unknown[] }).applications ?? (packagesPayload as { items?: unknown[] }).items ?? [])
    const source = (entries as unknown[]).find((entry) => {
      const record = entry as { id?: unknown; applicationId?: unknown }
      return record.id === packageId || record.applicationId === packageId
    })
    if (!source) throw new ClientError('http', `Package not found: ${packageId}`, { status: 404 })
    const view = mapPackage(source)
    if (!view.installAvailable) {
      throw new ClientError(
        'unavailable',
        'This package is not available for installation from the connected service',
        { detail: view.installUnavailableReason },
      )
    }
    if (!view.descriptorDigest || !view.packageDigest || !view.experienceDescriptorDigest) {
      throw new ClientError(
        'validation',
        'The service did not supply the descriptor digests required for a reviewed installation',
        { detail: 'Fixture installation is identity-bound: applicationDescriptorDigest, applicationPackageDigest and experienceDescriptorDigest are mandatory.' },
      )
    }
    const instanceId = newInstanceId()
    const receipt = await this.transport.request(endpoints.applicationFixtureInstall, {
      method: 'POST',
      body: {
        applicationId: packageId,
        instanceId,
        name: input.name,
        applicationDescriptorDigest: view.descriptorDigest.value,
        applicationPackageDigest: view.packageDigest.value,
        experienceDescriptorDigest: view.experienceDescriptorDigest.value,
      },
      schema: unknownPayload,
    })
    const mapped = mapInstallReceipt(receipt, {
      applicationId: packageId,
      instanceId,
    })
    // Read back the created instance (with its experience capabilities).
    // Always use the identity generated before the mutation. A response may
    // confirm that identity, but it may never redirect the follow-up read.
    const applications = new HttpApplicationsClient(this.transport)
    const instance = await applications.get(instanceId)
    return {
      instance,
      receipt: {
        id: mapped.receiptId,
        digest: mapped.receiptDigest,
      },
    }
  }

  async refresh(): Promise<void> {
    await this.transport.request(endpoints.catalogRefresh, { method: 'POST', schema: voidSchema })
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Repository import (exposed for future wiring)
// ─────────────────────────────────────────────────────────────────────────────

export class HttpRepositoryImportClient implements RepositoryImportClient {
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async listLocalCandidates() {
    const payload = await this.transport.request(endpoints.repositoryImportLocalCandidates, {
      schema: unknownPayload,
    })
    return mapRepositoryCandidates(payload)
  }

  async inspect(candidateId: string) {
    // Read-only: the service must not run repository code during inspection.
    const payload = await this.transport.request(endpoints.repositoryImportInspect, {
      method: 'POST',
      body: { candidateId },
      schema: unknownPayload,
    })
    const inspection = mapRepositoryInspection(payload)
    if (inspection.candidateId !== candidateId) {
      throw new ClientError(
        'validation',
        'Repository inspection returned a mismatched candidate identity',
        { detail: `expected ${candidateId}, got ${inspection.candidateId ?? 'missing'}` },
      )
    }
    return inspection
  }

  /** The status projection carries the exact local actor identity. */
  private actorId: string | null = null

  private async currentActorId(): Promise<string> {
    if (this.actorId) return this.actorId
    const payload = await this.transport.request(endpoints.status, { schema: unknownPayload })
    const wire = z
      .object({ actor: z.object({ actorId: z.string().optional() }).optional() })
      .passthrough()
      .parse(payload)
    const actorId = wire.actor?.actorId
    if (!actorId) {
      throw new ClientError('validation', 'The service status projection carried no actor identity')
    }
    this.actorId = actorId
    return actorId
  }

  async register(input: { candidateId: string; name: string; inspectionDigest: string; approved: boolean }) {
    if (!input.approved) {
      throw new ClientError('validation', 'Repository registration requires an explicit approval', {
        detail: 'Registration binds repository identity; approval is mandatory per the contract.',
      })
    }
    const actorId = await this.currentActorId()
    const instanceId = await externalInstanceIdForInspection(input.inspectionDigest)
    const payload = await this.transport.request(endpoints.repositoryImportRegister, {
      method: 'POST',
      body: {
        candidateId: input.candidateId,
        inspectionDigest: input.inspectionDigest,
        instanceId,
        name: input.name,
        approval: { decision: 'approve', actorId, proposalDigest: input.inspectionDigest },
      },
      schema: unknownPayload,
    })
    return mapRepositoryRegistration(payload, {
      candidateId: input.candidateId,
      inspectionDigest: input.inspectionDigest,
      instanceId,
    })
  }

  async installTemplate(input: {
    candidateId: string
    name: string
    inspection: RepositoryInspection
    approved: boolean
  }) {
    const template = input.inspection.template
    if (!input.approved) {
      throw new ClientError('validation', 'Template installation requires an explicit approval')
    }
    if (!template || template.validation.status !== 'passed') {
      throw new ClientError('validation', 'No validated template adapter is available for this repository')
    }
    const actorId = await this.currentActorId()
    const instanceId = await managedTemplateInstanceIdForInspection(input.inspection.inspectionDigest)
    const planPayload = await this.transport.request(endpoints.templateImportPlan, {
      method: 'POST',
      body: {
        candidateId: input.candidateId,
        inspectionDigest: input.inspection.inspectionDigest,
        instanceId,
        name: input.name,
      },
      schema: unknownPayload,
    })
    const plan = z
      .object({
        formatVersion: z.literal('stateport.template-import-plan/v1'),
        operation: z.literal('template-import'),
        candidateId: z.literal(input.candidateId),
        inspectionDigest: z.literal(input.inspection.inspectionDigest),
        instanceId: z.literal(instanceId),
        name: z.string().min(1),
        planDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        template: z.object({
          adapterId: z.literal(template.adapterId),
          applicationId: z.literal(template.applicationId),
        }).passthrough(),
      })
      .passthrough()
      .parse(planPayload)
    const resultPayload = await this.transport.request(endpoints.templateImportInstall, {
      method: 'POST',
      body: {
        plan,
        approval: { decision: 'approve', actorId, planDigest: plan.planDigest },
      },
      schema: unknownPayload,
    })
    const result = z
      .object({
        formatVersion: z.literal('stateport.template-install-result/v1'),
        instanceId: z.literal(instanceId),
        applicationId: z.literal(template.applicationId),
        conversationId: z.string().min(1),
        receiptId: z.string().min(1),
        receiptDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        sourceRepositoryMutated: z.literal(false),
        managedCopyCreated: z.literal(true),
      })
      .passthrough()
      .parse(resultPayload)
    return {
      instanceId: result.instanceId,
      conversationId: result.conversationId,
      receiptId: result.receiptId,
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings (global + per-application) with optimistic concurrency
// ─────────────────────────────────────────────────────────────────────────────

const GLOBAL_SETTINGS_OVERLAY_KEY = 'stateport.http.global-ui-settings.v1'
const APP_SETTINGS_OVERLAY_KEY = 'stateport.http.app-ui-settings.v1'

function mergeRecords<T>(base: T, patch: DeepPartial<T>): T {
  const visit = (left: unknown, right: unknown): unknown => {
    if (
      typeof left === 'object' && left !== null && !Array.isArray(left) &&
      typeof right === 'object' && right !== null && !Array.isArray(right)
    ) {
      const result: Record<string, unknown> = { ...(left as Record<string, unknown>) }
      for (const [key, value] of Object.entries(right as Record<string, unknown>)) {
        result[key] = visit(result[key], value)
      }
      return result
    }
    return right
  }
  return visit(base, patch) as T
}

function readLocalJson<T>(key: string, fallback: T): T {
  try {
    const raw = typeof localStorage !== 'undefined' ? localStorage.getItem(key) : null
    return raw ? mergeRecords(fallback, JSON.parse(raw) as DeepPartial<T>) : fallback
  } catch {
    return fallback
  }
}

function writeLocalJson(key: string, value: unknown): void {
  try {
    if (typeof localStorage !== 'undefined') localStorage.setItem(key, JSON.stringify(value))
  } catch {
    // Browser presentation preferences remain in-memory if storage is blocked.
  }
}

function uiOnlyGlobalSettings(settings: GlobalSettings): DeepPartial<GlobalSettings> {
  const copy = JSON.parse(JSON.stringify(settings)) as GlobalSettings
  if (copy.appearance.theme !== 'high_contrast') {
    delete (copy.appearance as Partial<GlobalSettings['appearance']>).theme
  }
  delete (copy.notifications as Partial<GlobalSettings['notifications']>).level
  if (copy.general.defaultLandingPage !== 'last_workspace') {
    delete (copy.general as Partial<GlobalSettings['general']>).defaultLandingPage
  }
  return copy
}

export class HttpGlobalSettingsClient implements GlobalSettingsClient {
  private revision: number | null = null
  private current: GlobalSettings | null = null
  private rollbackTargets: GlobalSettingsRollbackTarget[] = []
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async get(): Promise<GlobalSettings> {
    const payload = await this.transport.request(endpoints.settings, { schema: unknownPayload })
    const projection = mapGlobalSettings(payload, (candidate) => schemas.globalSettings.parse(candidate))
    this.revision = projection.revision
    this.rollbackTargets = projection.rollbackTargets
    const overlay = readLocalJson<DeepPartial<GlobalSettings>>(GLOBAL_SETTINGS_OVERLAY_KEY, {})
    this.current = schemas.globalSettings.parse(mergeRecords(projection.settings, overlay))
    return this.current
  }

  async getRollbackHistory(): Promise<GlobalSettingsRollbackHistory> {
    // Always refresh: the revision is authority-critical and another browser
    // or process may have changed settings since this client last loaded.
    await this.get()
    return {
      currentRevision: this.revision ?? 0,
      targets: this.rollbackTargets.map((target) => ({
        ...target,
        changes: { ...target.changes },
        previousValues: { ...target.previousValues },
      })),
    }
  }

  private async currentRevision(): Promise<number> {
    if (this.revision === null) await this.get()
    return this.revision ?? 0
  }

  async update(patch: DeepPartial<GlobalSettings>): Promise<GlobalSettings> {
    const expectedRevision = await this.currentRevision()
    const before = this.current ?? await this.get()
    const candidate = schemas.globalSettings.parse(mergeRecords(before, patch))
    const changes: Record<string, unknown> = {}
    if (candidate.appearance.theme !== before.appearance.theme && candidate.appearance.theme !== 'high_contrast') {
      changes['general.appearance'] = candidate.appearance.theme
    }
    if (candidate.notifications.level !== before.notifications.level) {
      changes['notifications.level'] =
        candidate.notifications.level === 'important_only' ? 'important' : candidate.notifications.level
    }
    if (
      candidate.general.defaultLandingPage !== before.general.defaultLandingPage &&
      candidate.general.defaultLandingPage === 'applications'
    ) {
      changes['general.defaultLandingView'] = 'home'
    }

    let serviceSettings = candidate
    if (Object.keys(changes).length > 0) {
      const payload = await this.transport.request(endpoints.settings, {
        method: 'POST',
        body: { expectedRevision, changes },
        schema: unknownPayload,
      })
      const projection = mapGlobalSettings(
        payload,
        (value) => schemas.globalSettings.parse(value),
        'settings.patch',
      )
      this.revision = projection.revision
      this.rollbackTargets = projection.rollbackTargets
      serviceSettings = schemas.globalSettings.parse(
        mergeRecords(projection.settings, uiOnlyGlobalSettings(candidate)),
      )
    }
    writeLocalJson(GLOBAL_SETTINGS_OVERLAY_KEY, uiOnlyGlobalSettings(candidate))
    this.current = serviceSettings
    return serviceSettings
  }

  async rollback(input: SettingsRollbackInput): Promise<GlobalSettings> {
    const payload = await this.transport.request(endpoints.settingsRollback, {
      method: 'POST',
      body: { expectedRevision: input.expectedRevision, receiptId: input.receiptId },
      schema: unknownPayload,
    })
    const projection = mapGlobalSettings(
      payload,
      (candidate) => schemas.globalSettings.parse(candidate),
      'settings.rollback',
    )
    this.revision = projection.revision
    this.rollbackTargets = projection.rollbackTargets
    this.current = schemas.globalSettings.parse(
      mergeRecords(
        projection.settings,
        readLocalJson<DeepPartial<GlobalSettings>>(GLOBAL_SETTINGS_OVERLAY_KEY, {}),
      ),
    )
    return this.current
  }

  /**
   * Derived: reset = an update carrying the shared frontend defaults. The
   * service stores the keys it owns; UI-only groups round-trip unchanged.
   */
  async reset(): Promise<GlobalSettings> {
    return this.update(defaultGlobalSettings())
  }

  /** Derived from get() — no separate endpoint required. */
  async exportJson(): Promise<string> {
    return JSON.stringify(await this.get(), null, 2)
  }

  /** Schema-validated, then applied through the normal update path. */
  async importJson(json: string): Promise<GlobalSettings> {
    assertSettingsImportSize(json)
    let candidate: unknown
    try {
      candidate = JSON.parse(json)
    } catch {
      throw new ClientError('validation', 'Settings import was not valid JSON')
    }
    const parsed = schemas.globalSettings.safeParse(candidate)
    if (!parsed.success) {
      throw new ClientError('validation', 'Settings import failed validation', {
        detail: parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n'),
      })
    }
    return this.update(parsed.data)
  }
}

export class HttpAppSettingsClient implements AppSettingsClient {
  private revisions = new Map<string, number>()
  private current = new Map<string, AppSettings>()
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async get(instanceId: string): Promise<AppSettings> {
    const payload = await this.transport.request(endpoints.appSettings(instanceId), { schema: unknownPayload })
    const projection = mapAppSettings(
      payload,
      instanceId,
      (candidate) => schemas.appSettings.parse(candidate),
      'settings.rollback',
    )
    this.revisions.set(instanceId, projection.revision)
    const overlays = readLocalJson<Record<string, DeepPartial<AppSettings>>>(APP_SETTINGS_OVERLAY_KEY, {})
    const settings = schemas.appSettings.parse(mergeRecords(projection.settings, overlays[instanceId] ?? {}))
    this.current.set(instanceId, settings)
    return settings
  }

  private async currentRevision(instanceId: string): Promise<number> {
    if (!this.revisions.has(instanceId)) await this.get(instanceId)
    return this.revisions.get(instanceId) ?? 0
  }

  async update(instanceId: string, patch: DeepPartial<AppSettings>): Promise<AppSettings> {
    await this.currentRevision(instanceId)
    const before = this.current.get(instanceId) ?? await this.get(instanceId)
    const settings = schemas.appSettings.parse(mergeRecords(before, patch))
    // The current backend application-settings projection is policy-owned
    // and read-only. These are explicitly browser presentation preferences;
    // no canonical or operational backend mutation is claimed.
    const overlays = readLocalJson<Record<string, DeepPartial<AppSettings>>>(APP_SETTINGS_OVERLAY_KEY, {})
    overlays[instanceId] = settings
    writeLocalJson(APP_SETTINGS_OVERLAY_KEY, overlays)
    this.current.set(instanceId, settings)
    return settings
  }

  async rollback(instanceId: string, input: SettingsRollbackInput): Promise<AppSettings> {
    const payload = await this.transport.request(endpoints.appSettingsRollback(instanceId), {
      method: 'POST',
      body: { expectedRevision: input.expectedRevision, receiptId: input.receiptId },
      schema: unknownPayload,
    })
    const projection = mapAppSettings(payload, instanceId, (candidate) => schemas.appSettings.parse(candidate))
    this.revisions.set(instanceId, projection.revision)
    this.current.set(instanceId, projection.settings)
    return projection.settings
  }

  /** Derived: reset = update with the shared per-instance defaults. */
  async reset(instanceId: string): Promise<AppSettings> {
    const overlays = readLocalJson<Record<string, DeepPartial<AppSettings>>>(APP_SETTINGS_OVERLAY_KEY, {})
    delete overlays[instanceId]
    writeLocalJson(APP_SETTINGS_OVERLAY_KEY, overlays)
    const settings = defaultAppSettings(instanceId)
    this.current.set(instanceId, settings)
    return settings
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Activity / attention / notifications
// ─────────────────────────────────────────────────────────────────────────────

export class HttpActivityClient implements ActivityClient {
  private readonly overlay = new OverlayStore()
  /** Per-attention-item expected versions for optimistic transitions. */
  private versions = new Map<string, number>()
  /** Activity/attention id → owning instance (from the last projection). */
  private owners = new Map<string, string>()
  /** Last-known attention items (for acknowledge responses). */
  private attentionCache = new Map<string, AttentionItem>()
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  private async targetInstances(instanceId?: string): Promise<string[]> {
    if (instanceId) return [instanceId]
    const payload = await this.transport.request(endpoints.instances, { schema: unknownPayload })
    return mapInstanceIndex(payload)
      .map((entry) => {
        const record = entry as { id?: unknown; instanceId?: unknown }
        return typeof record.id === 'string' ? record.id : record.instanceId
      })
      .filter((id): id is string => typeof id === 'string')
  }

  private async projectionFor(instanceId: string) {
    const payload = await this.transport.request(endpoints.activity(instanceId), { schema: unknownPayload })
    const projection = mapActivityProjection(payload, instanceId)
    for (const [attentionId, version] of Object.entries(projection.attentionVersions)) {
      this.versions.set(attentionId, version)
    }
    for (const item of projection.activity) this.owners.set(item.id, instanceId)
    for (const item of projection.attention) {
      this.owners.set(item.id, instanceId)
      this.attentionCache.set(item.id, item)
    }
    return projection
  }

  async listActivity(filter?: { instanceId?: string; unreadOnly?: boolean; limit?: number }): Promise<ActivityItem[]> {
    const ids = await this.targetInstances(filter?.instanceId)
    const projections = await Promise.all(ids.map((id) => this.projectionFor(id)))
    let items = projections.flatMap((p) => p.activity)
    if (filter?.unreadOnly) items = items.filter((i) => !i.read)
    items = items.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    return items.slice(0, filter?.limit ?? items.length)
  }

  private resolveOwner(id: string, context?: { instanceId?: string }): string {
    const instanceId = context?.instanceId ?? this.owners.get(id)
    if (!instanceId) {
      throw unavailable(
        'The owning application of this activity item is unknown',
        'List the activity first so the client can address the per-instance endpoint.',
      )
    }
    return instanceId
  }

  async markActivityRead(activityId: string, context?: { instanceId?: string }): Promise<void> {
    const instanceId = this.resolveOwner(activityId, context)
    const expectedVersion = this.versions.get(activityId)
    if (expectedVersion === undefined) {
      throw unavailable(
        'The attention item version is unknown',
        'Reload notifications before attempting the transition.',
      )
    }
    const payload = await this.transport.request(endpoints.attentionRead(instanceId, activityId), {
      method: 'POST',
      body: { expectedVersion },
      schema: unknownPayload,
    })
    if (payload === undefined) {
      this.versions.set(activityId, expectedVersion + 1)
      const known = this.attentionCache.get(activityId)
      if (known) this.attentionCache.set(activityId, { ...known, read: true })
      return
    }
    const record = payload as { attention?: unknown }
    const updated =
      record.attention !== undefined
        ? mapAttentionItem(record.attention, instanceId)
        : mapActivityProjection(payload, instanceId).attention.find((item) => item.id === activityId)
    if (!updated) {
      throw new ClientError('validation', 'The read attention item is not present in the service response')
    }
    this.versions.set(activityId, expectedVersion + 1)
    this.attentionCache.set(activityId, updated)
  }

  async listAttention(instanceId?: string): Promise<AttentionItem[]> {
    const ids = await this.targetInstances(instanceId)
    const projections = await Promise.all(ids.map((id) => this.projectionFor(id)))
    return projections
      .flatMap((p) => p.attention)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  }

  async acknowledgeAttention(attentionId: string, context?: { instanceId?: string }): Promise<AttentionItem> {
    const instanceId = this.resolveOwner(attentionId, context)
    const expectedVersion = this.versions.get(attentionId)
    if (expectedVersion === undefined) {
      throw unavailable(
        'The attention item version is unknown',
        'Reload attention before attempting the transition.',
      )
    }
    const payload = await this.transport.request(endpoints.attentionAcknowledge(instanceId, attentionId), {
      method: 'POST',
      body: { expectedVersion },
      schema: unknownPayload,
    })
    if (payload !== undefined) {
      const record = payload as { attention?: unknown }
      const updated =
        record.attention !== undefined
          ? mapAttentionItem(record.attention, instanceId)
          : mapActivityProjection(payload, instanceId).attention.find((a) => a.id === attentionId)
      if (updated) {
        this.versions.set(attentionId, expectedVersion + 1)
        this.attentionCache.set(attentionId, updated)
        return updated
      }
      throw new ClientError(
        'validation',
        'The acknowledged attention item is not present in the service response',
      )
    }
    // A 204/void success is also accepted for compatible services. Derive the
    // local projection only from the exact versioned item loaded beforehand.
    const known = this.attentionCache.get(attentionId)
    if (!known) {
      throw unavailable(
        'The acknowledged attention item is not present in the service response',
        'The service did not return the updated activity projection.',
      )
    }
    this.versions.set(attentionId, expectedVersion + 1)
    const derived = { ...known, read: true, acknowledged: true }
    this.attentionCache.set(attentionId, derived)
    return derived
  }

  /** Notifications are a projection of backend-owned attention, not receipts. */
  async listNotifications(): Promise<NotificationItem[]> {
    const ids = await this.targetInstances()
    const projections = await Promise.all(ids.map((id) => this.projectionFor(id)))
    return notificationsFromAttention(projections.flatMap((projection) => projection.attention)).map((n) => ({
      ...n,
      snoozedUntil: this.overlay.getSnoozed(n.id),
    }))
  }

  async markNotificationRead(notificationId: string, context?: { instanceId?: string }): Promise<void> {
    await this.markActivityRead(notificationId, context)
  }

  /** Snooze is user-local presentation state (no backend endpoint). */
  async snoozeNotification(notificationId: string, until: string): Promise<void> {
    this.overlay.snooze(notificationId, until)
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipts
// ─────────────────────────────────────────────────────────────────────────────

export class HttpReceiptsClient implements ReceiptsClient {
  /** receiptId → every owning instance observed; receipt IDs are not global. */
  private owners = new Map<string, Set<string>>()
  /** Includes closure receipts embedded in goal-execution projections. */
  private cache = new Map<string, Receipt>()
  /** Detail drawers can mount while their filtered list is still loading. */
  private pendingLists = new Set<Promise<Receipt[]>>()
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  private cacheKey(instanceId: string, receiptId: string): string {
    return `${instanceId}\u001f${receiptId}`
  }

  private remember(receipt: Receipt): Receipt {
    const owners = this.owners.get(receipt.id) ?? new Set<string>()
    owners.add(receipt.instanceId)
    this.owners.set(receipt.id, owners)
    this.cache.set(this.cacheKey(receipt.instanceId, receipt.id), receipt)
    return receipt
  }

  private cachedReceipt(
    receiptId: string,
    expectedInstanceId?: string,
  ): Receipt | undefined {
    if (expectedInstanceId !== undefined) {
      return this.cache.get(this.cacheKey(expectedInstanceId, receiptId))
    }
    const owners = this.owners.get(receiptId)
    if (!owners || owners.size === 0) return undefined
    if (owners.size > 1) {
      throw new ClientError(
        'validation',
        'The receipt identity is ambiguous across application instances',
        { detail: 'Open the receipt from an application-scoped route.' },
      )
    }
    const [owner] = owners
    return owner ? this.cache.get(this.cacheKey(owner, receiptId)) : undefined
  }

  private knownOwner(receiptId: string): string | undefined {
    const owners = this.owners.get(receiptId)
    if (!owners || owners.size === 0) return undefined
    if (owners.size > 1) {
      throw new ClientError(
        'validation',
        'The receipt identity is ambiguous across application instances',
        { detail: 'Open the receipt from an application-scoped route.' },
      )
    }
    return [...owners][0]
  }

  private async targetInstances(instanceId?: string): Promise<string[]> {
    if (instanceId) return [instanceId]
    const payload = await this.transport.request(endpoints.instances, { schema: unknownPayload })
    return mapInstanceIndex(payload)
      .map((entry) => {
        const record = entry as { id?: unknown; instanceId?: unknown }
        return typeof record.id === 'string' ? record.id : record.instanceId
      })
      .filter((id): id is string => typeof id === 'string')
  }

  list(filter?: { instanceId?: string; query?: string; result?: Receipt['result']; eventKind?: string; limit?: number; goalExecution?: boolean }): Promise<Receipt[]> {
    const task = this.listInternal(filter)
    this.pendingLists.add(task)
    void task.finally(() => this.pendingLists.delete(task)).catch(() => undefined)
    return task
  }

  private async listInternal(filter?: { instanceId?: string; query?: string; result?: Receipt['result']; eventKind?: string; limit?: number; goalExecution?: boolean }): Promise<Receipt[]> {
    const ids = await this.targetInstances(filter?.instanceId)
    // When the caller already knows the instance has no effective CTO
    // capability, do not issue the goal-execution poll the service must
    // refuse fail-closed (403); the closure receipt is unreachable anyway.
    const pollGoalExecution = filter?.goalExecution !== false
    const lists = await Promise.all(
      ids.map(async (instanceId) => {
        const [payload, goalPayload] = await Promise.all([
          this.transport.request(endpoints.receipts(instanceId), { schema: unknownPayload }),
          pollGoalExecution
            ? this.transport.request(endpoints.goalExecution(instanceId), { schema: unknownPayload }).catch((error: unknown) => {
                if (
                  error instanceof ClientError &&
                  error.kind === 'http' &&
                  (error.status === 403 || error.status === 404 || error.status === 409)
                ) {
                  return null
                }
                throw error
              })
            : Promise.resolve(null),
        ])
        const activityReceipts = mapReceiptIndex(payload, instanceId)
        const goalReceipt = goalPayload === null ? null : mapGoalExecutionReceipt(goalPayload, instanceId)
        return goalReceipt ? [...activityReceipts, goalReceipt] : activityReceipts
      }),
    )
    let items = [
      ...new Map(
        lists
          .flat()
          .map(
            (receipt) =>
              [this.cacheKey(receipt.instanceId, receipt.id), receipt] as const,
          ),
      ).values(),
    ]
    for (const receipt of items) {
      this.remember(receipt)
    }
    if (filter?.result) items = items.filter((r) => r.result === filter.result)
    if (filter?.eventKind) items = items.filter((r) => r.eventKind === filter.eventKind)
    if (filter?.query) {
      const q = filter.query.toLowerCase()
      items = items.filter((r) => `${r.actionName} ${r.summary} ${r.eventKind}`.toLowerCase().includes(q))
    }
    items = items.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    return items.slice(0, filter?.limit ?? items.length)
  }

  private bindExpectedInstance(receipt: Receipt, expectedInstanceId?: string): Receipt {
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
  }

  private bindExpectedId(receipt: Receipt, expectedReceiptId: string): Receipt {
    if (receipt.id !== expectedReceiptId) {
      throw new ClientError(
        'validation',
        'The receipt detail response did not match the requested receipt',
        { detail: `expected ${expectedReceiptId}, got ${receipt.id}` },
      )
    }
    return receipt
  }

  private bindExpectedReceipt(
    receipt: Receipt,
    expectedReceiptId: string,
    expectedInstanceId?: string,
  ): Receipt {
    return this.bindExpectedInstance(this.bindExpectedId(receipt, expectedReceiptId), expectedInstanceId)
  }

  async get(receiptId: string, expectedInstanceId?: string): Promise<Receipt> {
    const cached = this.cachedReceipt(receiptId, expectedInstanceId)
    if (cached) return this.bindExpectedReceipt(cached, receiptId, expectedInstanceId)
    if (this.pendingLists.size > 0) {
      await Promise.allSettled([...this.pendingLists])
      const discoveredByPendingList = this.cachedReceipt(
        receiptId,
        expectedInstanceId,
      )
      if (discoveredByPendingList) {
        return this.bindExpectedReceipt(discoveredByPendingList, receiptId, expectedInstanceId)
      }
    }
    let instanceId = expectedInstanceId ?? this.knownOwner(receiptId)
    if (!instanceId) {
      await this.list()
      const discovered = this.cachedReceipt(receiptId, expectedInstanceId)
      if (discovered) return this.bindExpectedReceipt(discovered, receiptId, expectedInstanceId)
      instanceId = expectedInstanceId ?? this.knownOwner(receiptId)
    }
    if (!instanceId) {
      throw unavailable(
        'The owning application of this receipt is unknown',
        'No current application projection owns this receipt identity.',
      )
    }
    const payload = await this.transport.request(endpoints.receipt(instanceId, receiptId), {
      schema: unknownPayload,
    })
    const record = payload as { receipt?: unknown; instanceId?: unknown }
    if (
      typeof record.instanceId === 'string' &&
      record.instanceId !== instanceId
    ) {
      throw new ClientError(
        'validation',
        'The receipt detail response carried a mismatched application identity',
        { detail: `expected ${instanceId}, got ${record.instanceId}` },
      )
    }
    const receipt = mapReceipt(record.receipt ?? payload, instanceId)
    return this.bindExpectedReceipt(this.remember(receipt), receiptId, expectedInstanceId)
  }

  /**
   * No verification endpoint exists in the contract — the UI must show its
   * honest unavailable state instead of a fabricated check.
   */
  verify(): Promise<{ ok: boolean; detail: string }> {
    return Promise.reject(
      unavailable(
        'Receipt verification is not available against the connected service',
        'The backend contract has no receipt verification endpoint.',
      ),
    )
  }

  /** Derived from list() — the JSON export of the already-loaded receipts. */
  async exportJson(instanceId: string): Promise<string> {
    return JSON.stringify(await this.list({ instanceId }), null, 2)
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Governed file workspace.
//
// The production adapter uses the existing application-scoped file-workspace
// broker. Reads bind content hash and Git base; writes always prepare, preview,
// confirm the exact diff digest, commit, and read back the recorded revision.
// Capability gating still hides the tool unless the effective experience
// declares file_viewer/editor.
// ─────────────────────────────────────────────────────────────────────────────

export class HttpFilesClient implements FilesClient {
  /** File content hash → the exact Git base SHA observed with that read. */
  private readonly baseShas = new Map<string, string>()
  /** Instance → exact Git base from one complete, non-truncated tree walk. */
  private readonly treeBaseShas = new Map<string, string>()
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  private key(instanceId: string, path: string): string {
    return `${instanceId}\u001f${path}`
  }

  private parseFileContract<T>(
    schema: z.ZodType<T>,
    payload: unknown,
    label: string,
  ): T {
    const parsed = schema.safeParse(payload)
    if (!parsed.success) {
      throw new ClientError('validation', `${label} did not match the current file-workspace contract`, {
        detail: parsed.error.issues
          .map((issue) => `${issue.path.join('.') || 'response'}: ${issue.message}`)
          .join('\n'),
      })
    }
    return parsed.data
  }

  private async getOperation(instanceId: string, operation: string, path: string): Promise<unknown> {
    const query = new URLSearchParams({ path })
    return this.transport.request(`${endpoints.fileWorkspace(instanceId, operation)}?${query}`, {
      schema: unknownPayload,
    })
  }

  private async postOperation(
    instanceId: string,
    operation: string,
    body: Record<string, unknown>,
  ): Promise<unknown> {
    return this.transport.request(endpoints.fileWorkspace(instanceId, operation), {
      method: 'POST',
      body,
      schema: unknownPayload,
    })
  }

  async listTree(instanceId: string): Promise<FileNode[]> {
    const listingSchema = z.object({
      operation: z.literal('listDirectory'),
      path: z.string(),
      baseSha: z.string(),
      truncated: z.boolean(),
      entries: z.array(z.object({
        path: z.string(),
        name: z.string(),
        kind: z.enum(['file', 'directory']),
        size: z.number().int().nonnegative().nullable(),
        readOnly: z.boolean(),
      })),
    })
    let seen = 0
    let observedBaseSha: string | null = null
    const walk = async (path: string, depth: number): Promise<FileNode[]> => {
      if (depth > 16 || seen > 5_000) {
        throw new ClientError('validation', 'The file tree exceeded the bounded frontend traversal policy')
      }
      const listing = listingSchema.parse(await this.getOperation(instanceId, 'listDirectory', path))
      if (observedBaseSha !== null && listing.baseSha !== observedBaseSha) {
        throw new ClientError('validation', 'The file tree changed Git identity during traversal')
      }
      observedBaseSha = listing.baseSha
      if (listing.truncated) {
        throw new ClientError('validation', `The directory listing for "${path || 'project root'}" was truncated`, {
          detail: 'Narrow the directory before relying on the file projection.',
        })
      }
      const nodes: FileNode[] = []
      for (const entry of listing.entries) {
        seen += 1
        nodes.push({
          path: entry.path,
          name: entry.name,
          kind: entry.kind,
          sizeBytes: entry.size ?? undefined,
          readOnly: entry.readOnly,
          children: entry.kind === 'directory' ? await walk(entry.path, depth + 1) : undefined,
        })
      }
      return nodes
    }
    const nodes = await walk('', 0)
    if (!observedBaseSha) {
      throw new ClientError('validation', 'The file broker omitted the project Git identity')
    }
    this.treeBaseShas.set(instanceId, observedBaseSha)
    return nodes
  }

  async read(instanceId: string, path: string): Promise<FileEntry> {
    const read = this.parseFileContract(z.object({
      formatVersion: z.literal('stateport.file-workspace/v1'),
      operation: z.literal('readFile'),
      content: z.string(),
      metadata: z.object({
        formatVersion: z.literal('stateport.file-workspace/v1'),
        operation: z.literal('readFileMetadata'),
        path: z.string(),
        size: z.number().int().nonnegative(),
        contentHash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        baseSha: z.string().regex(/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/),
        ownershipClass: z.enum(['application_owned', 'canonical', 'generated', 'disposable']),
        language: z.string(),
        readOnly: z.boolean(),
        encoding: z.literal('utf-8'),
        generated: z.boolean(),
        disposable: z.boolean(),
      }).strict(),
    }).strict(), await this.getOperation(instanceId, 'readFile', path), 'The file read response')
    if (read.metadata.path !== path) {
      throw new ClientError('validation', 'The file broker returned a different path identity')
    }
    this.baseShas.set(this.key(instanceId, path), read.metadata.baseSha)
    return {
      path,
      content: read.content,
      revision: read.metadata.contentHash,
      readOnly: read.metadata.readOnly,
      encoding: 'utf-8',
      // The current broker does not expose filesystem timestamps. Empty means
      // unavailable; it must not be presented as a backend-observed time.
      modifiedAt: '',
    }
  }

  async write(
    instanceId: string,
    path: string,
    input: { content: string; expectedRevision: string },
  ): ReturnType<FilesClient['write']> {
    const baseSha = this.baseShas.get(this.key(instanceId, path))
    if (!baseSha) {
      throw new ClientError('validation', 'The file must be read before it can be written', {
        detail: 'A governed write requires the exact content hash and Git base SHA from the same broker read.',
      })
    }
    let preparedWriteId: string | undefined
    try {
      const prepared = this.parseFileContract(z.object({
        formatVersion: z.literal('stateport.file-workspace/v1'),
        operation: z.literal('prepareWrite'),
        writeKind: z.literal('write'),
        preparedWriteId: z.string().min(1),
        path: z.string(),
        actorId: z.string().min(1),
        applicationId: z.string().min(1),
        instanceId: z.string().min(1),
        baseSha: z.string().regex(/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/),
        originalHash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        candidateHash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        ownershipClass: z.enum(['application_owned', 'canonical', 'generated', 'disposable']),
        expiresAt: z.iso.datetime(),
        requiresDiffConfirmation: z.literal(true),
        validationRequired: z.boolean(),
      }).strict(), await this.postOperation(instanceId, 'prepareWrite', {
        path,
        content: input.content,
        expectedContentHash: input.expectedRevision,
        expectedBaseSha: baseSha,
      }), 'The prepared write response')
      preparedWriteId = prepared.preparedWriteId
      if (
        prepared.instanceId !== instanceId ||
        prepared.path !== path ||
        prepared.originalHash !== input.expectedRevision ||
        prepared.baseSha !== baseSha
      ) {
        throw new ClientError('validation', 'The prepared write identity did not match the editor basis')
      }
      const preview = this.parseFileContract(z.object({
        formatVersion: z.literal('stateport.file-workspace/v1'),
        operation: z.literal('previewDiff'),
        preparedWriteId: z.string().min(1),
        path: z.string(),
        diff: z.string(),
        diffDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        originalHash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        candidateHash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        truncated: z.boolean(),
        confirmable: z.boolean(),
      }).strict(), await this.postOperation(instanceId, 'previewDiff', { preparedWriteId }), 'The file diff preview')
      if (
        preview.preparedWriteId !== preparedWriteId ||
        preview.path !== path ||
        preview.originalHash !== input.expectedRevision ||
        preview.candidateHash !== prepared.candidateHash ||
        preview.truncated ||
        !preview.confirmable
      ) {
        throw new ClientError('validation', 'The broker diff is not safely confirmable')
      }
      const receiptPayload = await this.postOperation(instanceId, 'commitWrite', {
        preparedWriteId,
        confirmedDiffDigest: preview.diffDigest,
      })
      preparedWriteId = undefined
      const wire = this.parseMutationReceipt(receiptPayload)
      if (
        wire.instanceId !== instanceId ||
        wire.applicationId !== prepared.applicationId ||
        wire.actorId !== prepared.actorId ||
        wire.operation !== 'commitWrite' ||
        wire.sourcePath !== path ||
        wire.destinationPath !== null ||
        wire.baseSha !== baseSha ||
        wire.preHash !== input.expectedRevision ||
        wire.postHash !== prepared.candidateHash ||
        wire.ownershipClass !== prepared.ownershipClass ||
        wire.diffDigest !== preview.diffDigest ||
        wire.validation !== (prepared.validationRequired ? 'passed' : 'not_required')
      ) {
        throw new ClientError('validation', 'The committed file receipt did not match the reviewed write')
      }
      const entry = await this.read(instanceId, path)
      const readbackBaseSha = this.baseShas.get(this.key(instanceId, path))
      if (
        entry.revision !== wire.postHash ||
        entry.content !== input.content ||
        readbackBaseSha !== baseSha
      ) {
        throw new ClientError('validation', 'The committed file could not be read back at the receipt revision')
      }
      const addedLines = preview.diff.split('\n').filter((line) => line.startsWith('+') && !line.startsWith('+++')).length
      const removedLines = preview.diff.split('\n').filter((line) => line.startsWith('-') && !line.startsWith('---')).length
      const diff: FileDiff = { unified: preview.diff, addedLines, removedLines }
      const receipt = mapReceipt({
        ...wire,
        id: wire.receiptId,
        result: 'applied',
        eventKind: `file.${wire.operation}`,
        actionName: wire.operation,
        expectedRevision: wire.preHash ?? undefined,
        resultRevision: wire.postHash ?? undefined,
        payloadDigest: wire.diffDigest ?? undefined,
        summary: `${wire.operation} ${path}`,
      }, instanceId)
      return {
        ok: true,
        change: {
          id: wire.receiptId,
          instanceId,
          path,
          beforeRevision: input.expectedRevision,
          afterRevision: entry.revision,
          diff,
          createdAt: wire.completedAt,
        },
        receipt,
        entry,
      }
    } catch (error) {
      if (preparedWriteId) {
        await this.postOperation(instanceId, 'discardWrite', { preparedWriteId }).catch(() => undefined)
      }
      if (error instanceof ClientError && error.status === 409) {
        try {
          const current = await this.read(instanceId, path)
          if (current.revision !== input.expectedRevision) {
            return {
              ok: false,
              reason: 'conflict',
              detail: 'The file changed on disk after it was opened.',
              currentRevision: current.revision,
              currentContent: current.content,
            }
          }
        } catch {
          // Preserve the original broker refusal when the re-read is denied.
        }
        const detail = error.message
        const lower = detail.toLowerCase()
        return {
          ok: false,
          reason: lower.includes('read-only')
            ? 'read_only'
            : lower.includes('path') || lower.includes('classified') || lower.includes('policy')
              ? 'path_policy'
              : 'validation',
          detail,
        }
      }
      throw error
    }
  }

  async create(
    instanceId: string,
    path: string,
    input: { content: string },
  ): Promise<CreateFileResult> {
    const baseSha = this.treeBaseShas.get(instanceId)
    if (!baseSha) {
      throw new ClientError('validation', 'The project tree must be listed before a file can be created', {
        detail: 'A governed create requires the exact Git base SHA from one complete broker listing.',
      })
    }
    let preparedWriteId: string | undefined
    try {
      const prepared = z.object({
        operation: z.literal('createFile'),
        writeKind: z.literal('create'),
        preparedWriteId: z.string(),
        path: z.string(),
        actorId: z.string(),
        applicationId: z.string(),
        instanceId: z.string(),
        baseSha: z.string(),
        originalHash: z.null(),
        candidateHash: z.string(),
        ownershipClass: z.string(),
        expiresAt: z.string(),
        requiresDiffConfirmation: z.literal(true),
        validationRequired: z.boolean(),
      }).parse(await this.postOperation(instanceId, 'createFile', {
        path,
        content: input.content,
        expectedBaseSha: baseSha,
      }))
      preparedWriteId = prepared.preparedWriteId
      if (
        prepared.instanceId !== instanceId ||
        prepared.path !== path ||
        prepared.baseSha !== baseSha
      ) {
        throw new ClientError('validation', 'The prepared create identity did not match the reviewed target')
      }
      const preview = z.object({
        operation: z.literal('previewDiff'),
        preparedWriteId: z.string(),
        path: z.string(),
        diff: z.string(),
        diffDigest: z.string(),
        originalHash: z.null(),
        candidateHash: z.string(),
        truncated: z.boolean(),
        confirmable: z.boolean(),
      }).parse(await this.postOperation(instanceId, 'previewDiff', { preparedWriteId }))
      if (
        preview.preparedWriteId !== preparedWriteId ||
        preview.path !== path ||
        preview.candidateHash !== prepared.candidateHash ||
        preview.truncated ||
        !preview.confirmable
      ) {
        throw new ClientError('validation', 'The new-file diff is not safely confirmable')
      }
      const rawReceipt = await this.postOperation(instanceId, 'commitWrite', {
        preparedWriteId,
        confirmedDiffDigest: preview.diffDigest,
      })
      preparedWriteId = undefined
      const wire = this.parseMutationReceipt(rawReceipt)
      if (
        wire.instanceId !== instanceId ||
        wire.applicationId !== prepared.applicationId ||
        wire.operation !== 'createFile' ||
        wire.sourcePath !== path ||
        wire.destinationPath !== null ||
        wire.baseSha !== baseSha ||
        wire.preHash !== null ||
        wire.postHash !== prepared.candidateHash ||
        wire.diffDigest !== preview.diffDigest
      ) {
        throw new ClientError('validation', 'The create receipt did not match the reviewed new file')
      }
      const entry = await this.read(instanceId, path)
      if (entry.revision !== wire.postHash || entry.content !== input.content) {
        throw new ClientError('validation', 'The created file could not be read back at the receipt revision')
      }
      await this.listTree(instanceId)
      return {
        ok: true,
        path,
        diff: this.diffFromUnified(preview.diff),
        receipt: this.mapMutationReceipt(wire, `Created ${path}`),
        entry,
      }
    } catch (error) {
      if (preparedWriteId) {
        await this.postOperation(instanceId, 'discardWrite', { preparedWriteId }).catch(() => undefined)
      }
      return this.expectedMutationFailure(error) ?? Promise.reject(error)
    }
  }

  async rename(
    instanceId: string,
    sourcePath: string,
    input: { destinationPath: string; expectedRevision: string },
  ): Promise<RenameFileResult> {
    const baseSha = this.requireReadBasis(instanceId, sourcePath)
    try {
      const wire = this.parseMutationReceipt(await this.postOperation(instanceId, 'renamePath', {
        sourcePath,
        destinationPath: input.destinationPath,
        expectedContentHash: input.expectedRevision,
        expectedBaseSha: baseSha,
      }))
      if (
        wire.instanceId !== instanceId ||
        wire.operation !== 'renamePath' ||
        wire.sourcePath !== sourcePath ||
        wire.destinationPath !== input.destinationPath ||
        wire.baseSha !== baseSha ||
        wire.preHash !== input.expectedRevision ||
        wire.postHash !== input.expectedRevision ||
        wire.diffDigest !== null
      ) {
        throw new ClientError('validation', 'The rename receipt did not match the reviewed file identities')
      }
      this.baseShas.delete(this.key(instanceId, sourcePath))
      const entry = await this.read(instanceId, input.destinationPath)
      if (entry.revision !== input.expectedRevision) {
        throw new ClientError('validation', 'The renamed file did not preserve the reviewed content revision')
      }
      const nodes = await this.listTree(instanceId)
      if (this.treeContains(nodes, sourcePath) || !this.treeContains(nodes, input.destinationPath)) {
        throw new ClientError('validation', 'The refreshed tree did not match the rename receipt')
      }
      return {
        ok: true,
        sourcePath,
        destinationPath: input.destinationPath,
        receipt: this.mapMutationReceipt(wire, `Renamed ${sourcePath} to ${input.destinationPath}`),
        entry,
      }
    } catch (error) {
      return this.expectedMutationFailure(error) ?? Promise.reject(error)
    }
  }

  async delete(
    instanceId: string,
    path: string,
    input: { expectedRevision: string },
  ): Promise<DeleteFileResult> {
    const baseSha = this.requireReadBasis(instanceId, path)
    try {
      const wire = this.parseMutationReceipt(await this.postOperation(instanceId, 'deletePath', {
        path,
        expectedContentHash: input.expectedRevision,
        expectedBaseSha: baseSha,
      }))
      if (
        wire.instanceId !== instanceId ||
        wire.operation !== 'deletePath' ||
        wire.sourcePath !== path ||
        wire.destinationPath !== null ||
        wire.baseSha !== baseSha ||
        wire.preHash !== input.expectedRevision ||
        wire.postHash !== null ||
        wire.diffDigest !== null
      ) {
        throw new ClientError('validation', 'The delete receipt did not match the reviewed file identity')
      }
      this.baseShas.delete(this.key(instanceId, path))
      const nodes = await this.listTree(instanceId)
      if (this.treeContains(nodes, path)) {
        throw new ClientError('validation', 'The deleted file still appeared in the refreshed tree')
      }
      return {
        ok: true,
        path,
        receipt: this.mapMutationReceipt(wire, `Deleted ${path}`),
      }
    } catch (error) {
      return this.expectedMutationFailure(error) ?? Promise.reject(error)
    }
  }

  private requireReadBasis(instanceId: string, path: string): string {
    const baseSha = this.baseShas.get(this.key(instanceId, path))
    if (!baseSha) {
      throw new ClientError('validation', 'The file must be read before its path can be changed', {
        detail: 'Rename and delete require the exact content hash and Git base SHA from the same broker read.',
      })
    }
    return baseSha
  }

  private parseMutationReceipt(payload: unknown) {
    return this.parseFileContract(z.object({
      formatVersion: z.literal('stateport.file-workspace/v1'),
      operation: z.enum(['commitWrite', 'createFile', 'renamePath', 'deletePath']),
      receiptId: z.string().min(1),
      actorId: z.string().min(1),
      applicationId: z.string().min(1),
      instanceId: z.string().min(1),
      sourcePath: z.string().min(1),
      destinationPath: z.string().min(1).nullable(),
      baseSha: z.string().regex(/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/),
      preHash: z.string().regex(/^sha256:[0-9a-f]{64}$/).nullable(),
      postHash: z.string().regex(/^sha256:[0-9a-f]{64}$/).nullable(),
      ownershipClass: z.enum(['application_owned', 'canonical', 'generated', 'disposable']),
      diffDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/).nullable(),
      validation: z.enum(['passed', 'not_required']),
      completedAt: z.iso.datetime(),
      contentRetained: z.literal(false),
    }).strict(), payload, 'The file mutation receipt')
  }

  private mapMutationReceipt(
    wire: ReturnType<HttpFilesClient['parseMutationReceipt']>,
    summary: string,
  ): Receipt {
    return mapReceipt({
      ...wire,
      id: wire.receiptId,
      result: 'applied',
      eventKind: `file.${wire.operation}`,
      actionName: wire.operation,
      expectedRevision: wire.preHash ?? undefined,
      resultRevision: wire.postHash ?? undefined,
      payloadDigest: wire.diffDigest ?? undefined,
      summary,
    }, wire.instanceId)
  }

  private diffFromUnified(unified: string): FileDiff {
    return {
      unified,
      addedLines: unified.split('\n').filter((line) => line.startsWith('+') && !line.startsWith('+++')).length,
      removedLines: unified.split('\n').filter((line) => line.startsWith('-') && !line.startsWith('---')).length,
    }
  }

  private treeContains(nodes: FileNode[], path: string): boolean {
    return nodes.some((node) => node.path === path || Boolean(node.children && this.treeContains(node.children, path)))
  }

  private expectedMutationFailure(error: unknown): FileMutationFailure | null {
    if (!(error instanceof ClientError) || (error.status !== 403 && error.status !== 409)) return null
    const lower = `${error.code ?? ''} ${error.message}`.toLowerCase()
    const reason: FileMutationFailure['reason'] =
      lower.includes('read-only')
        ? 'read_only'
        : lower.includes('changed') ||
            lower.includes('stale') ||
            lower.includes('concurrent') ||
            lower.includes('already exists') ||
            lower.includes('base')
          ? 'conflict'
          : lower.includes('path') ||
              lower.includes('classified') ||
              lower.includes('policy') ||
              lower.includes('access_denied') ||
              lower.includes('access denied')
            ? 'path_policy'
            : 'validation'
    return { ok: false, reason, detail: error.message }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Recovery
// ─────────────────────────────────────────────────────────────────────────────

export class HttpRecoveryClient implements RecoveryClient {
  private readonly transport: HttpTransport
  private readonly applications: ApplicationsClient

  constructor(transport: HttpTransport, applications: ApplicationsClient) {
    this.transport = transport
    this.applications = applications
  }

  async getBackupState(instanceId: string): Promise<ApplicationInstance['recovery']> {
    return (await this.applications.get(instanceId)).recovery
  }

  async runBackup(instanceId: string): Promise<{ recovery: ApplicationInstance['recovery']; receipt: Receipt }> {
    const payload = await this.transport.request(endpoints.backup(instanceId), {
      method: 'POST',
      body: {},
      schema: unknownPayload,
    })
    const receipt = await resolveReceipt(this.transport, instanceId, payload)
    // The validated mutation receipt is the authoritative completion result.
    // Do not turn that success into a failure by coupling it to a second GET:
    // a lost/malformed refresh response would invite the user to repeat a
    // backup that the service already completed.
    return {
      recovery: {
        state: receipt.result === 'validated' ? 'current' : 'running',
        lastBackupAt: receipt.createdAt,
        lastReceiptId: receipt.id,
        detail:
          receipt.result === 'validated'
            ? 'The backup receipt records local validation.'
            : 'The backup receipt was recorded; refresh recovery status for the latest verification detail.',
      },
      receipt,
    }
  }

  async getStatus(instanceId: string): Promise<RecoveryStatus> {
    return this.transport.request(endpoints.recovery(instanceId), {
      schema: recoveryStatusWire,
    }) as Promise<RecoveryStatus>
  }

  async planRestore(
    instanceId: string,
    input: {
      backupReceiptId: string
      destinationInstanceId: string
      destinationName: string | null
    },
  ): Promise<RestorePlan> {
    return this.transport.request(endpoints.restorePlan(instanceId), {
      method: 'POST',
      body: input,
      schema: restorePlanWire,
    }) as Promise<RestorePlan>
  }

  async approveRestore(instanceId: string, planDigest: string): Promise<RestoreApproval> {
    return this.transport.request(endpoints.restoreApprove(instanceId), {
      method: 'POST',
      body: { planDigest },
      schema: restoreApprovalWire,
    }) as Promise<RestoreApproval>
  }

  async applyRestore(
    instanceId: string,
    input: { planDigest: string; approvalDigest: string },
  ): Promise<RestoreReceipt> {
    return this.transport.request(endpoints.restoreApply(instanceId), {
      method: 'POST',
      body: input,
      schema: restoreReceiptWire,
    }) as Promise<RestoreReceipt>
  }

}

/**
 * Responses carry either a full receipt object, a `receiptId` reference, or
 * the backup subsystem's explicitly named `backupReceipt`.
 */
export async function resolveReceipt(transport: HttpTransport, instanceId: string, payload: unknown): Promise<Receipt> {
  const record = (payload ?? {}) as {
    receipt?: unknown
    receiptId?: unknown
    backupReceipt?: unknown
  }
  if (record.receipt !== undefined) return mapReceipt(record.receipt, instanceId)
  if (record.backupReceipt !== undefined) {
    return mapReceipt(record.backupReceipt, instanceId)
  }
  if (typeof record.receiptId === 'string') {
    const detail = await transport.request(endpoints.receipt(instanceId, record.receiptId), {
      schema: unknownPayload,
    })
    return mapReceipt(detail, instanceId)
  }
  // Some endpoints return the receipt object directly.
  try {
    return mapReceipt(payload, instanceId)
  } catch {
    throw new ClientError('validation', 'The service response carried no receipt', {
      detail:
        'Expected a receipt object, a backupReceipt object, or a receiptId reference.',
    })
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Operations — derived from runs + infrastructure (Level B; no stream endpoint)
// ─────────────────────────────────────────────────────────────────────────────

/** Backend run states from which POST /v1/runs/:id/cancel is accepted. */
const CANCELLABLE_RUN_STATES: ReadonlySet<OperationRecord['state']> = new Set([
  'awaiting_approval',
  'approved',
  'prepared',
  'running',
  'cancelling',
  'interrupted',
])

export class HttpOperationsClient implements OperationsClient {
  private readonly transport: HttpTransport
  private readonly runs: Pick<import('../client').RunsClient, 'getHistory' | 'transition'>
  private readonly infrastructure: Pick<import('../client').InfrastructureClient, 'getTarget' | 'listPlans'>

  constructor(
    transport: HttpTransport,
    runs: Pick<import('../client').RunsClient, 'getHistory' | 'transition'>,
    infrastructure: Pick<import('../client').InfrastructureClient, 'getTarget' | 'listPlans'>,
  ) {
    this.transport = transport
    this.runs = runs
    this.infrastructure = infrastructure
  }

  async list(): Promise<OperationRecord[]> {
    const payload = await this.transport.request(endpoints.instances, { schema: unknownPayload })
    const ids = mapInstanceIndex(payload)
      .map((entry) => (entry as { id?: unknown }).id)
      .filter((id): id is string => typeof id === 'string')
    const records: OperationRecord[] = []
    for (const instanceId of ids) {
      const history = await this.runs.getHistory(instanceId).catch(() => [])
      for (const run of history) {
        records.push({
          id: `op_${run.id}`,
          instanceId,
          kind: 'orchestration_run',
          title: `Run ${run.actionId}`,
          state: run.state,
          stageLabel: run.state.replaceAll('_', ' '),
          startedAt: run.createdAt,
          updatedAt: run.updatedAt,
          canPause: false,
          canCancel: CANCELLABLE_RUN_STATES.has(run.state),
          log: [],
          relatedReceiptId: run.receiptId,
        })
      }
      const plans = await this.infrastructure.listPlans(instanceId).catch(() => [])
      for (const plan of plans) {
        records.push({
          id: `op_${plan.id}`,
          instanceId,
          kind: 'infrastructure_plan',
          title: plan.title,
          state: plan.state,
          stageLabel: plan.operation.replaceAll('_', ' '),
          startedAt: plan.createdAt,
          updatedAt: plan.createdAt,
          canPause: false,
          canCancel: false,
          log: [],
          relatedPlanId: plan.id,
          relatedReceiptId: plan.receiptId,
        })
      }
    }
    return records.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
  }

  async get(operationId: string): Promise<OperationRecord> {
    const found = (await this.list()).find((o) => o.id === operationId)
    if (!found) throw new ClientError('http', `Operation not found: ${operationId}`, { status: 404 })
    return found
  }

  /** No pause endpoint exists in the contract. */
  pause(): Promise<OperationRecord> {
    return Promise.reject(
      unavailable('Pausing operations is not supported by the connected service', 'The backend contract has no run pause endpoint.'),
    )
  }

  /**
   * Cancel a run-backed operation through the backend's idempotent cancel
   * transition (`POST /v1/runs/:id/cancel`). Infrastructure plans have no
   * cancel transition and fail closed.
   */
  async cancel(operationId: string): Promise<OperationRecord> {
    const record = await this.get(operationId)
    if (record.kind !== 'orchestration_run') {
      throw unavailable(
        'Cancelling this operation is not supported by the connected service',
        'Only run-backed operations expose a backend cancel transition.',
      )
    }
    if (!CANCELLABLE_RUN_STATES.has(record.state)) {
      throw new ClientError('http', 'This operation cannot be cancelled from its current state', { status: 409 })
    }
    const runId = operationId.slice('op_'.length)
    const run = (await this.runs.getHistory(record.instanceId)).find((candidate) => candidate.id === runId)
    if (!run) throw new ClientError('http', `Run not found: ${runId}`, { status: 404 })
    const updated = await this.runs.transition(runId, 'cancel', {
      expectedInstanceId: record.instanceId,
      expectedRevision: run.revision,
    })
    return {
      ...record,
      state: updated.state,
      stageLabel: updated.state.replaceAll('_', ' '),
      updatedAt: updated.updatedAt,
      canCancel: CANCELLABLE_RUN_STATES.has(updated.state),
      relatedReceiptId: updated.receiptId ?? record.relatedReceiptId,
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario Lab — development-only; unavailable against the real service.
// ─────────────────────────────────────────────────────────────────────────────

export class HttpScenarioClient implements ScenarioClient {
  private error(): ClientError {
    return unavailable(
      'Scenario Lab is only available with the mock adapter',
      'Scenarios are a development feature; the production service has no scenario endpoint.',
    )
  }
  list(): ReturnType<ScenarioClient['list']> {
    throw this.error()
  }
  getActive(): ReturnType<ScenarioClient['getActive']> {
    // Honest "no active scenario" — the lab overlay stays closed.
    return Promise.resolve(null)
  }
  setActive(): ReturnType<ScenarioClient['setActive']> {
    throw this.error()
  }
  resetMockState(): ReturnType<ScenarioClient['resetMockState']> {
    throw this.error()
  }
}
