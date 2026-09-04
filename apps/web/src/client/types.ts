/**
 * StatePort domain types — the single typed vocabulary shared by the mock
 * adapter, the future HTTP adapter, and every UI surface.
 *
 * Conventions:
 * - IDs are stable strings with a recognizable prefix (`ins_…`, `rcpt_…`,
 *   `appr_…`, `plan_…`, `op_…`, `msg_…`, `term_…`, `att_…`, `authz_…`,
 *   `orch_…`, `pkg_…`, `conv_…`, `ntf_…`, `act_…`, `attn_…`).
 * - Timestamps are ISO 8601 strings (UTC). Relative display is a UI concern.
 * - Nothing here references UI concepts; the semantic status layer
 *   (`src/semantic.ts`) maps these states to presentation.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Semantic status layer (design.md §7)
// ─────────────────────────────────────────────────────────────────────────────

export type SemanticState =
  | 'success'
  | 'neutral'
  | 'attention'
  | 'waiting'
  | 'blocked'
  | 'danger'
  | 'informational'

/** The honest operation states (design.md §7.1). Never collapsed into one. */
export type OperationState =
  | 'draft'
  | 'proposed'
  | 'preparing'
  | 'prepared'
  | 'awaiting_approval'
  | 'approved'
  | 'queued'
  | 'running'
  | 'completed'
  | 'cancelling'
  | 'paused'
  | 'interrupted'
  | 'applied'
  | 'validating'
  | 'validated'
  | 'completed_without_change'
  | 'rejected'
  | 'cancelled'
  | 'blocked'
  | 'unavailable'
  | 'failed'
  | 'human_accepted'

/**
 * What the receipt itself records. These claims intentionally remain
 * separate: approval is not execution, execution is not apply, apply is not
 * validation, and validation is not human acceptance.
 */
export type ReceiptResult =
  | 'approved'
  | 'applied'
  | 'executed'
  | 'completed'
  | 'validated'
  | 'completed_without_change'
  | 'rejected'
  | 'cancelled'
  | 'failed'
  | 'human_accepted'

/** Validation evidence recorded independently from the receipt result. */
export type ReceiptValidationState =
  | 'not_recorded'
  | 'not_required'
  | 'validating'
  | 'validated'
  | 'failed'

// ─────────────────────────────────────────────────────────────────────────────
// Capabilities
// ─────────────────────────────────────────────────────────────────────────────

export type CapabilityId =
  | 'conversation'
  | 'workbench'
  | 'file_viewer'
  | 'editor'
  | 'terminal'
  | 'progress_dashboard'
  | 'goal_execution'
  | 'cto_orchestration'
  | 'benchmark_evidence'
  | 'proactive_notifications'
  | 'backup'
  | 'infrastructure'
  | 'receipts'

export type CapabilityStatus =
  | 'available'
  | 'degraded'
  | 'environment_gated'
  | 'unavailable'

export interface CapabilityState {
  id: CapabilityId
  status: CapabilityStatus
  /** Plain-language explanation shown on demand for non-available states. */
  reason?: string
}

// ─────────────────────────────────────────────────────────────────────────────
// Application packages and instances
// ─────────────────────────────────────────────────────────────────────────────

export type PackageId = string

/**
 * StatePort-owned component identifiers accepted by the backend experience
 * contract. A package may select one of these identifiers; it never supplies
 * executable frontend code.
 */
export type ApplicationExperienceComponent =
  | 'activity_history'
  | 'application_home'
  | 'backup_manager'
  | 'benchmark_evidence'
  | 'context_summary'
  | 'conversation_thread'
  | 'cost_summary'
  | 'cto_orchestration'
  | 'development_workbench'
  | 'editor_surface'
  | 'file_viewer'
  | 'goal_actions'
  | 'notification_feed'
  | 'permission_summary'
  | 'progress_overview'
  | 'receipt_list'
  | 'run_history'
  | 'state_summary'
  | 'terminal_surface'
  | 'update_manager'

export type ApplicationNavigationPlacement =
  | 'application'
  | 'conversation'
  | 'advanced'

/** One backend-resolved declarative view; visibility is already policy-bound. */
export interface ResolvedApplicationView {
  viewId: string
  label: string
  component: ApplicationExperienceComponent
  /** Descriptor route retained as evidence; the frontend never navigates to it directly. */
  declaredRoute: string
  capability: CapabilityId
  status: CapabilityStatus
  reasons: string[]
  visible: boolean
}

/** Ordered contribution referencing a resolved view by immutable descriptor id. */
export interface ResolvedApplicationNavigation {
  contributionId: string
  label: string
  viewId: string
  placement: ApplicationNavigationPlacement
  order: number
  visible: boolean
}

/**
 * One backend-resolved progressive control. Like resolved views, controls are
 * declarative selection evidence only; the browser still requires an exact
 * match in its static StatePort-owned control registry before exposing a
 * route.
 */
export interface ResolvedApplicationAdvancedControl {
  controlId: string
  label: string
  component: ApplicationExperienceComponent
  capability: CapabilityId
  order: number
  status: CapabilityStatus
  reasons: string[]
  visible: boolean
}

/**
 * Browser projection of the backend-owned resolved experience. This is
 * descriptive selection data only: it cannot grant capabilities, register
 * routes, or load package code.
 */
export interface ResolvedApplicationExperience {
  formatVersion: 'stateport.application-experience-resolution/v1'
  applicationId: string
  descriptorDigest?: PlanDigest
  views: ResolvedApplicationView[]
  navigation: ResolvedApplicationNavigation[]
  advancedControls: ResolvedApplicationAdvancedControl[]
}

export type NetworkPolicy = 'none' | 'local_only' | 'restricted' | 'full'

export interface PackagePermissions {
  /** Human summary lines for the install-review step (plain language first). */
  fileAccess: string
  terminalAccess: string
  networkAccess: string
  dataOwnership: string
}

export interface ApplicationPackage {
  id: PackageId
  /** Machine identity, e.g. `project-state`. */
  name: string
  displayName: string
  description: string
  version: string
  releaseStatus: 'stable' | 'beta' | 'experimental'
  reviewClassification: 'reviewed' | 'community'
  capabilities: CapabilityId[]
  views: string[]
  permissions: PackagePermissions
  networkPolicy: NetworkPolicy
  dataBoundaries: string[]
  workbenchTools: WorkbenchToolId[]
  /** Explicit source claims; absence is unknown, never an affirmative claim. */
  productionEligible?: boolean
  publicSafe?: boolean
  sourceKind?: string
  privacyClassification?: string
}

export type WorkbenchToolId =
  | 'overview'
  | 'files'
  | 'terminal'
  | 'deployments'
  | 'orchestration'
  | 'receipts'

/** Top-line instance condition. Mapped by the semantic layer, never by color. */
export type InstanceHealth =
  | 'ready'
  | 'attention_needed'
  | 'degraded'
  | 'blocked'
  | 'offline'

export interface RepositoryIdentity {
  name: string
  branch: string
  revision: string
  /** Dirty = uncommitted changes exist (attention, not danger). */
  clean: boolean
}

/**
 * Browser-safe source identity from the existing application inspection
 * projection. Exact Git fields contain only full object IDs; legacy fixture
 * references are kept separate so they cannot be mistaken for Git evidence.
 */
export interface ApplicationSourceIdentity {
  /** StatePort owns an isolated working copy; the original repository is unchanged. */
  management?: 'isolated_template'
  templateId?: string
  adapterId?: string
  declaredTemplateId?: string
  declaredVersion?: string
  repository?: string
  resolvedCommit?: string
  resolvedTree?: string
  manifestDigest?: string
  sourceDigest?: string
  sourceKind?: string
  sourceClass?: string
  sourceAccessClass?: 'canonical_release' | 'development_candidate'
  ownership?: string
  version?: string
  productionEligible?: boolean
  productionInstallAllowed?: boolean
  /** Import materialized the committed Git snapshot, excluding working-tree edits. */
  workingTreeChangesExcluded?: boolean
  /** Raw compatibility reference, never presented as an exact Git commit. */
  compatibilityRevision?: string
  /** Raw compatibility tree reference paired with `compatibilityRevision`. */
  compatibilityTree?: string
}

export type ApplicationOwnershipCategory =
  | 'template'
  | 'instance'
  | 'generated'
  | 'override'

export interface ApplicationOwnershipProjection {
  counts: Record<ApplicationOwnershipCategory, number>
  /**
   * Bounded, application-relative paths only. Absolute paths, traversal, and
   * local checkout locations are rejected by the HTTP normalization boundary.
   */
  paths: Record<ApplicationOwnershipCategory, string[]>
  truncated: Record<ApplicationOwnershipCategory, boolean>
}

/**
 * Read-only provenance projected by `PersistentApp.inspect()`. This is
 * application-scoped evidence, not a second source registry or lifecycle
 * authority.
 */
export interface ApplicationProvenance {
  source: ApplicationSourceIdentity
  ownership?: ApplicationOwnershipProjection
}

// ── Canonical application sources ──────────────────────────────────────────

export type CanonicalSourceStatus =
  | 'awaiting_verified_release'
  | 'source_available'
  | 'rejected'

/**
 * Browser-safe source status. This intentionally excludes repository,
 * immutable object, local-path, candidate, parser, and credential details.
 */
export interface CanonicalSourcePublicView {
  formatVersion: 'stateport.canonical-source-public-view/v1'
  sourceId: string
  applicationId: string
  publicName: string
  status: CanonicalSourceStatus
  installable: boolean
  productionAction: {
    action: 'install_or_update'
    enabled: boolean
  }
  message: string
}

/** Immutable remote identity allowed only in the operator projection. */
export interface CanonicalSourceIdentity {
  repository: string
  commit: string
  tree: string
  manifestDigest: string
  sourceDigest: string
}

export interface CanonicalSourceOperatorView {
  formatVersion: 'stateport.canonical-source-operator-view/v1'
  sourceId: string
  application: {
    id: string
    publicName: string
    legacyIdentifiers: string[]
  }
  authority: {
    repository: string
    canonicalRefPolicy: string
    manifestPath: string
    manifestContract: string
  }
  canonicalRelease: {
    sourceClass: 'canonical_release'
    identity: CanonicalSourceIdentity | null
    status: CanonicalSourceStatus
    trust: 'unverified' | 'development_only' | 'verified_release' | 'rejected'
    installable: boolean
    missingRequirement: string | null
    requiredModules: string[]
    expectedSelfTests: string[]
  }
  developmentCandidate: {
    sourceClass: 'development_candidate'
    releaseStatus: 'candidate'
    testingAllowed: boolean
    productionInstallAllowed: false
    identity: CanonicalSourceIdentity
    verifiedModules: string[]
    verifiedSelfTests: string[]
    verificationAction: {
      enabled: boolean
      acknowledgement: string
      purpose: 'isolated_development_verification_only'
    }
  } | null
  message: string
}

export interface DevelopmentSourceVerificationInput {
  sourceId: string
  sourceClass: 'development_candidate'
  expectedCommit: string
  expectedTree: string
  expectedManifestDigest: string
  expectedSourceDigest: string
  acknowledgement: string
}

export interface DevelopmentSourceResolution {
  formatVersion: 'stateport.development-source-resolution/v1'
  sourceId: string
  applicationId: string
  sourceClass: 'development_candidate'
  identity: CanonicalSourceIdentity
  releaseStatus: 'candidate'
  trust: 'development_only'
  productionInstallAllowed: false
  verifiedModules: string[]
  requiredSelfTests: string[]
  selfTestDeclarationsMatched: boolean
  selfTestsExecutedByThisOperation: boolean
  verifiedAt: string
  receiptDigest: string
}

export interface RecoveryInfo {
  state: 'current' | 'due' | 'running' | 'failed' | 'not_configured'
  lastBackupAt?: string
  nextDueAt?: string
  lastReceiptId?: string
  detail?: string
}

type RestorePlannedSourceAccess =
  | { disposition: 'not_propagated' }
  | {
      disposition: 'propagate_exact_receipt'
      sourceAccessClass: 'canonical_release'
      productionInstallAllowed: true
      sourceReceiptDigest: string
    }
  | {
      disposition: 'propagate_exact_receipt'
      sourceAccessClass: 'development_candidate'
      productionInstallAllowed: false
      sourceReceiptDigest: string
    }

type RestoreReceiptSourceAccess =
  | { disposition: 'not_propagated' }
  | {
      disposition: 'propagated'
      sourceAccessClass: 'canonical_release'
      productionInstallAllowed: true
      sourceReceiptDigest: string
      destinationReceiptDigest: string
    }
  | {
      disposition: 'propagated'
      sourceAccessClass: 'development_candidate'
      productionInstallAllowed: false
      sourceReceiptDigest: string
      destinationReceiptDigest: string
    }

export interface RestorePlan {
  formatVersion: 'stateport.restore-plan/v1'
  operation: 'restore_new_instance'
  sourceInstanceId: string
  destinationInstanceId: string
  destinationName: string
  identityPolicy: 'reidentify'
  backup: {
    receiptId: string
    receiptDigest: string
    createdAt: string
    archiveDigest: string
    archiveFileDigest: string
    manifestDigest: string
    sourceLockDigest: string
    fileCount: number
    storageLocation: 'stateport_managed_backup_root'
  }
  preconditions: {
    sourceBindingDigest: string
    destinationRootClass: 'stateport_managed_instances_root'
    destinationAbsent: true
    destinationCatalogIdentityAbsent: true
  }
  dryRun: { status: 'verified'; instanceId: string; fileCount: number; archiveDigest: string }
  effects: {
    sourceCanonicalState: 'unchanged'
    destinationCanonicalState: 'new_instance_created'
    externalEffectsRestored: false
    overwriteAllowed: false
    sourceAccess: RestorePlannedSourceAccess
  }
  limitations: string[]
  createdAt: string
  expiresAt: string
  planDigest: string
}

export interface RestoreApproval {
  formatVersion: 'stateport.restore-approval/v1'
  operation: 'restore_new_instance'
  sourceInstanceId: string
  destinationInstanceId: string
  planDigest: string
  actor: { actorId: string; actorRole: 'platform_operator' | 'local_operator' }
  decision: 'approved'
  approvedAt: string
  expiresAt: string
  approvalDigest: string
}

export interface RestoreReceipt {
  formatVersion: 'stateport.restore-receipt/v1'
  receiptId: string
  operation: 'restore_new_instance'
  status: 'validated'
  sourceInstanceId: string
  destinationInstanceId: string
  planDigest: string
  approvalDigest: string
  backup: RestorePlan['backup']
  result: {
    identityPolicy: 'reidentify'
    instanceId: string
    fileCount: number
    archiveDigest: string
    baseGit: string
    validation: { valid: true; issues: [] }
    catalogIdentity: Record<string, unknown>
  }
  effects: {
    sourceCanonicalState: 'unchanged'
    destinationCanonicalState: 'new_instance_created'
    externalEffectsRestored: false
    sourceAccess: RestoreReceiptSourceAccess
  }
  createdAt: string
  receiptDigest: string
}

export interface RecoveryStatus {
  formatVersion: 'stateport.recovery-status/v1'
  sourceInstanceId: string
  status: 'no_backup' | 'verified' | 'degraded'
  latest: null | {
    instanceId: string
    archiveDigest: string
    archiveFileDigest: string
    createdAt: string
    validation: 'verified'
    backupReceipt: { receiptId: string }
    storageLocation: 'stateport_managed_backup_root'
  }
  operatorInspectionRequired?: boolean
  verificationIssues?: string[]
  restore: {
    status: 'not_planned' | 'planned' | 'approved' | 'validated' | 'failed'
    latestPlanDigest: string | null
    latestApprovalDigest: string | null
    latestReceiptId: string | null
    operatorInspectionRequired: boolean
    stagingRetained?: boolean
    destinationInstanceId?: string
    expiresAt?: string
    failureReasonCode?: string
  }
  limitations: {
    filesystemStateOnly: true
    externalEffectsRestored: false
    overwriteRestoreSupported: false
  }
}

// ── Package-specific state (capability-driven overview sections) ─────────────

export interface StudyActivity {
  id: string
  title: string
  reason?: string
  state: 'not_started' | 'in_progress' | 'paused' | 'done'
  updatedAt: string
}

export interface StudyEvidence {
  id: string
  title: string
  state: 'missing' | 'draft' | 'self_reported' | 'verified'
  updatedAt: string
}

export interface StudyStatePackageData {
  kind: 'study-state'
  goal: string
  goalProgressPercent: number
  activities: StudyActivity[]
  evidence: StudyEvidence[]
  /** Digest of the durable goal + ordered activity plan, excluding evidence text. */
  planDigest?: string
  /** True only when the backend proves the last durable transition is reversible. */
  canUndo?: boolean
  lastTransition?: Record<string, unknown>
}

export interface ChecklistItem {
  id: string
  title: string
  done: boolean
  updatedAt: string
}

export interface ChecklistPackageData {
  kind: 'checklist-state'
  items: ChecklistItem[]
}

export type PackageStateData = StudyStatePackageData | ChecklistPackageData

export interface ApplicationInstance {
  id: string
  /** User-owned name — the primary identity everywhere. */
  name: string
  packageId: PackageId
  packageName: string
  packageDisplayName: string
  health: InstanceHealth
  attention: AttentionItem[]
  recentActivity: ActivityItem[]
  settings: AppSettings
  /**
   * Exact durable conversation identity when the backend projects it.
   * Absence remains absence; application projections must never synthesize
   * an authority identity from the instance id.
   */
  conversationId?: string
  capabilities: CapabilityState[]
  /** Present when the connected backend supplied a resolved experience. */
  experience?: ResolvedApplicationExperience
  /**
   * Whether the connected backend resolved the experience authority.
   * Absence is reserved for explicitly supported legacy/mock projections;
   * `unavailable` must never activate capability-only legacy routes.
   */
  experienceResolution?: 'resolved' | 'unavailable'
  receiptIds: string[]
  recovery: RecoveryInfo
  repository?: RepositoryIdentity
  /** Existing backend inspection evidence, normalized for browser safety. */
  provenance?: ApplicationProvenance
  runtimeIdentity?: string
  /** Typed package-specific state for capability-driven overview sections. */
  packageState?: PackageStateData
  pinned: boolean
  createdAt: string
  lastOpenedAt?: string
}

// ─────────────────────────────────────────────────────────────────────────────
// Catalog
// ─────────────────────────────────────────────────────────────────────────────

export interface CatalogPackage {
  pkg: ApplicationPackage
  installedInstanceCount: number
  updateAvailable?: { fromVersion: string; toVersion: string; releaseNotes: string }
  /** Whether installing this package requires an approval before first run. */
  installRequiresApproval: boolean
  /** False when the backend says this exact package identity is not installable. */
  installAvailable?: boolean
  /** Plain-language reason retained from the backend's install projection. */
  installUnavailableReason?: string
}

/** Exact result of one reviewed application installation mutation. */
export interface CatalogInstallResult {
  instance: ApplicationInstance
  receipt: {
    id: string
    /** Digest of the durable operations/application-installs receipt payload. */
    digest: PlanDigest
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversation
// ─────────────────────────────────────────────────────────────────────────────

export type ConversationChannel = 'web' | 'telegram'

export type AttachmentState = 'uploading' | 'ready' | 'failed'

export interface Attachment {
  id: string
  name: string
  mimeType: string
  sizeBytes: number
  state: AttachmentState
  /** 0–100 while uploading. */
  progress?: number
  error?: string
  retentionNote?: string
}

export type ContextChipKind =
  | 'application'
  | 'file'
  | 'selection'
  | 'terminal'
  | 'plan'
  | 'approval'
  | 'receipt'
  | 'summary'

export interface ContextChip {
  id: string
  kind: ContextChipKind
  /** Human label, e.g. `flake.nix` or `Current plan`. */
  label: string
  /** ID of the referenced entity when there is one. */
  refId?: string
  detail?: string
  removable: boolean
}

export type MessageState = 'complete' | 'streaming' | 'stopped' | 'failed'

export interface ToolEvent {
  id: string
  /** e.g. `terminal.run`, `file.read`, `plan.prepare`. */
  kind: string
  summary: string
  detail?: string
  state: OperationState
  createdAt: string
}

export interface ConversationMessage {
  id: string
  conversationId: string
  role: 'user' | 'assistant' | 'system'
  /** Markdown body (rendered sanitized; no raw HTML). */
  content: string
  createdAt: string
  state: MessageState
  attachments: Attachment[]
  contextChips: ContextChip[]
  toolEvents: ToolEvent[]
  /** Set when the message carries a governed-operation proposal card. */
  proposal?: {
    title: string
    detail: string
    /** Where the proposal leads (approvals inbox, plan review, …). */
    actionRoute?: string
  }
}

export interface Conversation {
  id: string
  instanceId: string
  title: string
  channel: ConversationChannel
  deliveryState: 'delivered' | 'pending' | 'failed' | 'not_configured'
  retentionNote: string
  messages: ConversationMessage[]
  createdAt: string
  updatedAt: string
}

/** Streaming contract chunks yielded by `streamMessage()`. */
export type ConversationStreamChunk =
  | { type: 'delta'; text: string }
  | { type: 'done'; message: ConversationMessage }
  | { type: 'accepted'; message: string }
  | { type: 'stopped'; message: ConversationMessage }
  | { type: 'error'; message: string }

export interface MessageStream {
  /** ID of the assistant response, or a transient response identity when none is produced. */
  readonly messageId: string
  [Symbol.asyncIterator](): AsyncIterator<ConversationStreamChunk>
  /** Idempotent: safe to call after completion. */
  stop(): void
}

// ─────────────────────────────────────────────────────────────────────────────
// Files
// ─────────────────────────────────────────────────────────────────────────────

export type FileGitStatus = 'clean' | 'modified' | 'untracked' | 'locked'

export interface FileNode {
  path: string
  name: string
  kind: 'file' | 'directory'
  sizeBytes?: number
  modifiedAt?: string
  readOnly?: boolean
  gitStatus?: FileGitStatus
  children?: FileNode[]
}

export interface FileEntry {
  path: string
  content: string
  /** Opaque revision token; required as `expectedRevision` on write. */
  revision: string
  readOnly: boolean
  encoding: 'utf-8'
  modifiedAt: string
}

export interface FileDiff {
  /** Unified diff text. */
  unified: string
  addedLines: number
  removedLines: number
}

export interface FileChange {
  id: string
  instanceId: string
  path: string
  beforeRevision: string
  afterRevision: string
  diff: FileDiff
  createdAt: string
}

/** Expected broker refusals (transport and malformed-response failures still throw). */
export interface FileMutationFailure {
  ok: false
  reason: 'conflict' | 'path_policy' | 'read_only' | 'validation'
  detail: string
  /** Present on an edit conflict so the UI can offer reload/merge. */
  currentRevision?: string
  currentContent?: string
}

/** Domain-expected write outcomes (transport failures still throw ClientError). */
export type WriteFileResult =
  | { ok: true; change: FileChange; receipt: Receipt; entry: FileEntry }
  | FileMutationFailure

/** A reviewed create returns the exact committed entry and diff receipt. */
export type CreateFileResult =
  | { ok: true; path: string; diff: FileDiff; receipt: Receipt; entry: FileEntry }
  | FileMutationFailure

/** Rename preserves the read revision while changing the application-scoped path. */
export type RenameFileResult =
  | { ok: true; sourcePath: string; destinationPath: string; receipt: Receipt; entry: FileEntry }
  | FileMutationFailure

/** Delete proves the exact read revision was removed and returns its receipt. */
export type DeleteFileResult =
  | { ok: true; path: string; receipt: Receipt }
  | FileMutationFailure

// ─────────────────────────────────────────────────────────────────────────────
// Terminal
// ─────────────────────────────────────────────────────────────────────────────

export interface TerminalTarget {
  id: string
  instanceId: string
  label: string
  kind: 'local_pty' | 'ssh'
  available: boolean
  unavailableReason?: string
}

export type TerminalSessionState =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'failed'
  | 'ended'

export interface TerminalSession {
  id: string
  targetId: string
  instanceId: string
  name: string
  state: TerminalSessionState
  cwd: string
  createdAt: string
  lastError?: string
}

export type TerminalSessionEvent =
  | { type: 'state'; state: TerminalSessionState; error?: string }
  | { type: 'output'; text: string }
  | { type: 'exit'; code: number }

export interface CommandResult {
  output: string
  exitCode: number
}

// ─────────────────────────────────────────────────────────────────────────────
// Infrastructure
// ─────────────────────────────────────────────────────────────────────────────

export type VMPowerState =
  | 'not_defined'
  | 'stopped'
  | 'starting'
  | 'running'
  | 'stopping'
  | 'unavailable'

export type SSHState =
  | 'not_checked'
  | 'ready'
  | 'unavailable_vm_not_defined'
  | 'unavailable_vm_stopped'
  | 'failed'

export type HealthState = 'not_checked' | 'checking' | 'healthy' | 'unhealthy' | 'unavailable'

export interface InfrastructureTarget {
  id: string
  instanceId: string
  name: string
  kind: 'local_vm'
  available: boolean
  unavailableReason?: string
  repository: RepositoryIdentity
  vm: { state: VMPowerState; since?: string }
  ssh: { state: SSHState; detail?: string }
  health: { state: HealthState; checkedAt?: string; detail?: string }
}

export type InfrastructureOperation =
  | 'observe'
  | 'validate'
  | 'health_check'
  | 'create_or_update'
  | 'start'
  | 'stop'
  | 'restart'
  | 'destroy'

export interface PlanDigest {
  algorithm: 'sha256'
  value: string
}

export interface PlanStep {
  id: string
  title: string
  /** Exact command or check, mono-rendered by the UI. */
  detail: string
  kind: 'command' | 'check' | 'gate'
}

export type RiskLevel = 'low' | 'medium' | 'high'

export interface InfrastructurePlan {
  id: string
  instanceId: string
  targetId: string
  operation: InfrastructureOperation
  title: string
  state: OperationState
  risk: RiskLevel
  requiresApproval: boolean
  /** True when a daily-driver authorization already covers this operation. */
  coveredByAuthorization: boolean
  steps: PlanStep[]
  digest: PlanDigest
  beforeSummary: string
  afterSummary: string
  rollbackNotes: string
  approvalId?: string
  receiptId?: string
  createdAt: string
}

export type PlanProgressEvent =
  | { type: 'state'; planId: string; state: OperationState }
  | { type: 'step'; planId: string; stepIndex: number; stepState: OperationState }
  | { type: 'log'; planId: string; line: string }
  | { type: 'done'; planId: string; receipt: Receipt }
  | { type: 'error'; planId: string; message: string }

// ─────────────────────────────────────────────────────────────────────────────
// Daily-driver authorization
// ─────────────────────────────────────────────────────────────────────────────

export type AuthorizationStatus = 'proposed' | 'active' | 'expired' | 'revoked'

export interface AuthorizationGrant {
  id: string
  instanceId: string
  targetId: string
  status: AuthorizationStatus
  /** Operations covered, e.g. observe/validate/health_check/start/stop/restart. */
  covers: InfrastructureOperation[]
  /** Plain-language lines for what remains separately gated. */
  doesNotCover: string[]
  createdAt: string
  /** Absent for grants governed by target/repository identity rather than time. */
  expiresAt?: string
  createdByReceiptId?: string
  revokedAt?: string
  revokeReceiptId?: string
}

// ─────────────────────────────────────────────────────────────────────────────
// Approvals
// ─────────────────────────────────────────────────────────────────────────────

export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired'

export type ApprovalKind =
  | 'infrastructure_plan'
  | 'orchestration_run'
  | 'authorization_grant'
  | 'goal_execution'
  | 'template_upgrade'
  | 'file_write'
  | 'capability_change'

export type ApprovalDecisionKind =
  | 'run_approval'
  | 'run_proposal'
  | 'infrastructure_plan'
  | 'authorization_grant'
  | 'goal_execution'
  | 'template_upgrade'

export interface ApprovalDecision {
  /** Typed authoritative mutation; never infer this from the presentation title. */
  kind: ApprovalDecisionKind
  expectedInstanceId: string
  /** Exact optimistic-concurrency revision for governed run/goal decisions. */
  expectedRevision?: number
  /** Exact run specification, proposal, plan, or grant digest. */
  expectedDigest: string
}

interface ApprovalBase {
  id: string
  instanceId: string
  /** Human title, e.g. "Start virtual machine". */
  title: string
  operationType: string
  risk: RiskLevel
  status: ApprovalStatus
  /** Exact scope lines, plain language. */
  scope: string[]
  beforeSummary: string
  afterSummary: string
  /** Unified diff when the change is textual. */
  diff?: FileDiff
  planDigest: PlanDigest
  planId?: string
  /**
   * Set when the approval references a governed execution run — the HTTP
   * adapter routes the decision to `/v1/runs/:runId/…` (there is no generic
   * approval decision endpoint in the backend contract).
   */
  runId?: string
  /** Why approval is required (linked policy explanation). */
  whyRequired: string
  requestedAt: string
  /** Absent for identity-bound requests that do not expire automatically. */
  expiresAt?: string
  /** Exact backend authority and identities used to route this decision. */
  /** Digest of current underlying state; mismatch with planDigest ⇒ stale. */
  currentDigest?: PlanDigest
  decidedAt?: string
  decisionReason?: string
  resultingReceiptId?: string
  relatedConversationId?: string
}

export type Approval =
  | (ApprovalBase & {
      kind: 'template_upgrade'
      targetId: string
      decision: ApprovalDecision & { kind: 'template_upgrade' }
    })
  | (ApprovalBase & {
      kind: Exclude<ApprovalKind, 'template_upgrade'>
      targetId?: string
      decision: ApprovalDecision & {
        kind: Exclude<ApprovalDecisionKind, 'template_upgrade'>
      }
    })

// ─────────────────────────────────────────────────────────────────────────────
// Receipts
// ─────────────────────────────────────────────────────────────────────────────

export type ActorKind = 'user' | 'assistant' | 'system'

export interface Receipt {
  id: string
  instanceId: string
  packageId: PackageId
  /** Human-facing action name, e.g. "File change saved". */
  actionName: string
  /** Raw event kind, e.g. `file.write`. Detail surfaces only. */
  eventKind: string
  actor: ActorKind
  result: ReceiptResult
  createdAt: string
  expectedRevision?: string
  resultRevision?: string
  planDigest?: PlanDigest
  payloadDigest?: PlanDigest
  validation: { state: ReceiptValidationState; detail: string }
  summary: string
  beforeSummary?: string
  afterSummary?: string
  diff?: FileDiff
  relatedOperationId?: string
  relatedConversationId?: string
  relatedApprovalId?: string
  relatedPlanId?: string
  /** Canonical raw payload for the detail drawer. */
  rawJson: string
}

// ─────────────────────────────────────────────────────────────────────────────
// Operation center (long-running operations)
// ─────────────────────────────────────────────────────────────────────────────

export interface OperationRecord {
  id: string
  instanceId: string
  kind: 'infrastructure_plan' | 'orchestration_run' | 'backup' | 'export'
  title: string
  state: OperationState
  stageLabel: string
  /** 0–100 when determinate. */
  progressPercent?: number
  startedAt: string
  updatedAt: string
  canPause: boolean
  canCancel: boolean
  log: string[]
  relatedPlanId?: string
  relatedReceiptId?: string
  error?: string
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestration (bounded CTO slice)
// ─────────────────────────────────────────────────────────────────────────────

export type OrchestrationMode =
  | 'advisory'
  | 'assisted'
  | 'managed_approved_queue'
  | 'off'

/** The 13-stage flow from the brief. */
export type OrchestrationStage =
  | 'enter_objective'
  | 'select_mode'
  | 'prepare_slice'
  | 'review_base'
  | 'review_plan'
  | 'review_permissions'
  | 'review_budget'
  | 'approve'
  | 'run'
  | 'review_result'
  | 'independent_review'
  | 'close'
  | 'receipt'

export interface OrchestrationBudget {
  maxOperations: number
  maxMinutes: number
  usedOperations: number
  usedMinutes: number
}

export interface OrchestrationSession {
  id: string
  instanceId: string
  objective: string
  mode: OrchestrationMode
  stage: OrchestrationStage
  state: OperationState
  baseIdentity: RepositoryIdentity
  scope: string[]
  permissions: string[]
  budget: OrchestrationBudget
  implementer: string
  reviewer: string
  resultSummary?: string
  receiptId?: string
  createdAt: string
  updatedAt: string
}

/** Typed availability of the governed execution backend behind orchestration. */
export interface OrchestrationBackendAvailability {
  status: 'available' | 'unavailable'
  backendId?: string
  /** True marks the test-only synthetic backend — never provider execution. */
  testOnly?: boolean
  code?: string
  message?: string
  nextAction?: string
}

/**
 * The current orchestration view: session plus the exact backend identity
 * behind it. `backendId`, `providerExecution`, and `canonicalStateEffect`
 * are retained end-to-end (service projection → API schema → this type →
 * durable receipt) so a fabricated execution can never present as real.
 */
export interface OrchestrationView {
  session: OrchestrationSession | null
  backendId?: string | null
  providerExecution: boolean
  canonicalStateEffect?: string
  backendAvailability?: OrchestrationBackendAvailability
}

// ─────────────────────────────────────────────────────────────────────────────
// Governed execution (runs domain — backed by /v1/instances/:id/execution/*)
// ─────────────────────────────────────────────────────────────────────────────

/** Run transition operations accepted by `POST /v1/runs/:runId/<operation>`. */
export type RunOperation =
  | 'approve'
  | 'execute'
  | 'cancel'
  | 'proposal-approve'
  | 'proposal-reject'
  | 'apply'

/**
 * Exact persisted status vocabulary from
 * `stateport.governed-action-run/v1`.
 *
 * This remains separate from the coarser `OperationState` presentation
 * vocabulary: notably `approved` and `state_change_approved` authorize
 * different next operations and must never be collapsed for control logic.
 */
export type RunStatus =
  | 'requested'
  | 'planned'
  | 'awaiting_approval'
  | 'approved'
  | 'preparing'
  | 'prepared'
  | 'running'
  | 'awaiting_tool_approval'
  | 'cancelling'
  | 'cancelled'
  | 'interrupted'
  | 'timed_out'
  | 'failed'
  | 'completed'
  | 'result_validating'
  | 'result_rejected'
  | 'state_change_proposed'
  | 'state_change_approved'
  | 'state_change_rejected'
  | 'applying'
  | 'applied'
  | 'apply_failed'
  | 'archived'

/** Exact explicit lifecycle vocabulary persisted beside the legacy status. */
export type RunLifecycleState =
  | 'DRAFT'
  | 'COMPILED'
  | 'BLOCKED_CAPABILITY'
  | 'AWAITING_RUN_APPROVAL'
  | 'APPROVED'
  | 'STARTING'
  | 'RUNNING'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'CANCELLED'
  | 'INTERRUPTED'
  | 'TIMED_OUT'
  | 'RESULT_VALIDATED'
  | 'NO_MUTATION'
  | 'PROPOSAL_CREATED'
  | 'AWAITING_PROPOSAL_APPROVAL'
  | 'PROPOSAL_REJECTED'
  | 'APPLYING'
  | 'APPLIED'
  | 'POST_VALIDATED'
  | 'CLOSED'
  | 'ROLLED_BACK'

export interface GovernedAction {
  id: string
  instanceId: string
  /** Human title, e.g. "Validate the flake". */
  title: string
  description?: string
  /**
   * Optional explicit engine allow-list. Current application-action/v1
   * contracts do not declare one, so an empty list means engine negotiation is
   * governed by the action capabilities and the selected runtime profile.
   */
  engineIds: string[]
  formatVersion?: 'stateport.application-action/v1'
  inputSchema?: Record<string, unknown>
  outputSchema?: Record<string, unknown>
  contextPolicy?: Record<string, unknown>
  requiredCapabilities?: string[]
  optionalCapabilities?: string[]
  mutationPolicy?: string
  networkPolicy?: string
  toolPolicy?: string
  timeoutSeconds?: number
  budgetDefaults?: Record<string, number>
  validationPolicy?: Record<string, unknown>
  supportedEngineDegradations?: string[]
  expectedEvidenceArtifacts?: string[]
  executorCommand?: string
}

export type ExecutionEngineAvailability =
  | 'available'
  | 'environment_gated'
  | 'unavailable'

export interface ExecutionEngine {
  id: string
  label: string
  kind: string
  /** Exact backend availability classification. */
  availability: ExecutionEngineAvailability
  /** Convenience projection: true only for exact `availability: available`. */
  available: boolean
  unavailableReason?: string
  formatVersion?: 'stateport.execution-engine/v1'
  adapterId?: string
  adapterVersion?: string
  installedVersion?: string
  authenticationRouteClass?: string
  capabilities?: Record<string, string>
  modelIdentity?: string
  productionEligible?: boolean
  limitations?: string[]
}

export interface RunEvent {
  type: string
  at?: string
  from?: string
  to?: string
  fromLifecycle?: RunLifecycleState
  toLifecycle?: RunLifecycleState
  actor?: string
  reason?: string
}

export interface RunRecord {
  id: string
  instanceId: string
  actionId: string
  engineId: string
  /**
   * Coarse semantic presentation only. Transition controls must use `status`
   * when it is present, because distinct backend statuses can share this
   * presentation state.
   */
  state: OperationState
  /** Exact backend status; optional only for legacy/mock consumer fixtures. */
  status?: RunStatus
  /** Exact explicit backend lifecycle; optional only for legacy fixtures. */
  lifecycleState?: RunLifecycleState
  lifecycleVersion?: 'stateport.run-lifecycle/v1'
  formatVersion?: 'stateport.governed-action-run/v1'
  /** Monotonic optimistic-concurrency counter; transitions must increase it. */
  revision: number
  inputs: Record<string, unknown>
  proposalDigest?: PlanDigest
  proposal?: Record<string, unknown>
  runSpecDigest?: PlanDigest
  runSpec?: Record<string, unknown>
  negotiation?: Record<string, unknown>
  executionGate?: Record<string, unknown>
  result?: Record<string, unknown>
  postApplyValidation?: Record<string, unknown>
  rollback?: Record<string, unknown>
  /** Application-writer receipt; it does not itself prove StatePort closure. */
  receipt?: Record<string, unknown>
  /** Exact StatePort receipt created only after apply, local validation, and closure. */
  closureReceipt?: Record<string, unknown>
  receiptId?: string
  events?: RunEvent[]
  approvalRequired?: boolean
  createdAt: string
  updatedAt: string
}

export interface RunTransitionInput {
  expectedInstanceId: string
  expectedRevision: number
}

export interface RunBundle {
  runId: string
  applied: boolean
  formatVersion: 'stateport.run-bundle/v1'
  contentDigest: PlanDigest
  fileCount: number
  verified: boolean
  /**
   * Compatibility fields for the existing detail component. The live bundle
   * endpoint does not carry a run projection, event transcript, or receipt
   * index, so these remain empty rather than being invented.
   */
  run?: RunRecord
  events: string[]
  receiptIds: string[]
}

export interface StateBenchCheck {
  id: string
  title: string
  state: OperationState
  detail?: string
}

export interface StateBenchResult {
  subjectId: string
  applied: boolean
  row: StateBenchRunBundleRow
  /**
   * Coarse run-status presentation, never a synthesized benchmark verdict.
   * Individual `checks` below are direct projections of row facts.
   */
  state: OperationState
  checks: StateBenchCheck[]
  receiptId?: string
}

export interface StateBenchRunBundleRow {
  formatVersion: 'statebench.run-bundle-row/v1'
  integrityStatus: 'verified'
  authoritative: false
  producerClaimsTrusted: false
  bundleDigest: PlanDigest
  runId: string
  applicationId: string
  engineId: string
  adapterId: string
  status: RunStatus
  statePreserved: boolean
  capabilityDegradations: Array<Record<string, unknown>>
  acceptedRun: boolean
  usageAvailable: boolean | null
  latencyMs: number | null
  unauthorizedMutations: number
  bundleFileCount: number
}

export interface PlatformStateBenchDegradation {
  id: string
  status?: string
}

/**
 * Closed, path-free row returned by the operator-only platform projection.
 *
 * This deliberately remains separate from `StateBenchRunBundleRow`: the
 * platform endpoint exposes a stricter degradation shape and the exact
 * serialized bundle digest. Neither row type is a score or promotion result.
 */
export interface PlatformStateBenchRow {
  formatVersion: 'statebench.run-bundle-row/v1'
  integrityStatus: 'verified'
  authoritative: false
  producerClaimsTrusted: false
  bundleDigest: string
  runId: string
  applicationId: string
  engineId: string
  adapterId: string
  status: RunStatus
  statePreserved: boolean
  capabilityDegradations: PlatformStateBenchDegradation[]
  acceptedRun: boolean
  usageAvailable: boolean | null
  latencyMs: number | null
  unauthorizedMutations: number
  bundleFileCount: number
}

export interface PlatformStateBenchView {
  formatVersion: 'stateport.platform-statebench-view/v1'
  rows: PlatformStateBenchRow[]
  verifiedRowCount: number
  rejectedOrUnverifiedCount: number
  truncated: boolean
  hardOutcomeOnly: true
  authoritativePerformanceClaim: false
  calibrationMeaning: 'Harness behavior only; comparative performance is not established.'
}

// ─────────────────────────────────────────────────────────────────────────────
// Context lifecycle
// ─────────────────────────────────────────────────────────────────────────────

export type ContextPreference = 'faster' | 'balanced' | 'deeper'

export interface ContextModeOption {
  id: ContextPreference
  label: string
  description: string
}

export interface ContextEffectivePolicyView {
  formatVersion: 'stateport.context-lifecycle-effective/v1'
  sourcePolicies: {
    scope: string
    policyId: string
    digest: string
  }[]
  unresolvedPolicyScopes: string[]
  budget: {
    maximumInputTokens: number
    preferredInputTokens: number
  }
  compression: {
    mode: string
    triggerRatio: number
    preserve: string[]
  }
  handoff: {
    mode: string
    triggerRatio: number
    createArtifact: boolean
    requireReceipt: boolean
  }
  session: { resumeOnlyWhen: string[] }
  contextCategories: {
    included: string[]
    excluded: string[]
  }
  bindingReasons: Record<string, string[]>
  authorityClassification: 'operational_noncanonical'
  canonicalStateMutation: false
  effectivePolicyDigest: string
}

export interface ContextUsageView {
  formatVersion: 'stateport.context-usage/v1'
  inputTokens: number | null
  quality: 'observed' | 'estimated' | 'unavailable'
  source: 'provider_reported' | 'stateport_estimator' | 'unavailable'
}

export interface ContextGitIdentityView {
  repositoryId: string
  branch: string
  baseSha: string
  headSha: string
  treeSha: string
  worktreeStatusDigest: string
  worktreeClean: boolean
}

/** Backend continuity truth for manual context transitions. */
export interface ContextContinuityView {
  available: boolean
  reasonCode?: string | null
  manualCompactAvailable: boolean
  manualHandoffAvailable: boolean
  continuityDigest: string | null
  conversationId: string | null
  workstreamId: string | null
  expectedBaseSha: string | null
  expectedPolicyDigest: string | null
}

/** Exact identities required for a manual compact/handoff transition. */
export interface ContextTransitionBinding {
  expectedBaseSha: string
  expectedPolicyDigest: string
  expectedContinuityDigest: string
}

export interface ContextSegment {
  id: string
  kind: string
  label: string
  /** Approximate token footprint for the visualization. */
  tokens: number
  pinned: boolean
}

export interface ContextLifecycle {
  formatVersion: 'stateport.context-lifecycle-view/v1'
  instanceId: string
  /** Digest of the effective context policy (optimistic concurrency). */
  policyDigest: PlanDigest
  effectivePolicy: ContextEffectivePolicyView
  preference: ContextPreference
  availableModes: ContextModeOption[]
  /** The backend never accepts raw prompt overrides through this surface. */
  rawPromptFieldsAllowed: boolean
  /** Human-facing token-usage statement (estimator quality included). */
  usageDisplay: string
  usage: ContextUsageView
  gitIdentity: ContextGitIdentityView | null
  gitIdentityReason: string | null
  continuity: ContextContinuityView
  storedRecordCount: number
  defaultsEvidence: 'candidate_not_benchmarked'
  authorityClassification: 'operational_noncanonical'
  canonicalStateMutation: false
  /** Mock/Scenario Lab visualization segments; empty in production. */
  segments: ContextSegment[]
}

export interface ContextTransitionResult {
  lifecycle: ContextLifecycle
  /** Present when the transition produced an auditable receipt. */
  receiptId?: string
  summary: string
}

// ─────────────────────────────────────────────────────────────────────────────
// Local repository import
// ─────────────────────────────────────────────────────────────────────────────

export interface RepositoryCandidate {
  /** Opaque allowlisted candidate identity (never a raw filesystem path). */
  candidateId: string
  displayName: string
  /** Safe display location relative to an allowlisted root. */
  relativeLocation: string
  /** Set when the service can suggest a matching application package. */
  suggestedPackageId?: string
}

export interface RepositoryFinding {
  code: string
  severity: 'warning' | 'error'
  message: string
}

export interface RepositoryTemplateMatch {
  formatVersion: 'stateport.template-adapter-match/v1'
  adapterId: string
  applicationId: string
  displayName: string
  description: string
  templateKind: string
  declaredTemplateId?: string
  declaredVersion?: string
  markerFiles: string[]
  requestedCapabilities: string[]
  trustedActionIds: string[]
  executionTrust: 'stateport_owned_adapter_only'
  repositoryCommandsExecuted: false
  validation: {
    status: 'passed' | 'failed'
    issues: Array<{ code: string; message: string }>
  }
}

export interface RepositoryInspection {
  candidateId?: string
  /** Safe display source (relative location or URL), never an absolute path. */
  source: string
  /** Read-only inspection digest — required to register. */
  inspectionDigest: string
  branch: string
  headCommit: string
  dirty: boolean
  /** StateSpec classification reported by the inspector (opaque summary). */
  stateSpec?: unknown
  /** A reviewed StatePort-owned adapter detected from bounded declarative markers. */
  template?: RepositoryTemplateMatch
  findings: RepositoryFinding[]
  /** The backend inspection never mutates or executes the repository. */
  /** Undefined means the inspector did not prove that it was read-only. */
  mutated?: boolean
}

export interface RepositoryRegistration {
  instanceId: string
  conversationId?: string
  receiptId?: string
}

// ─────────────────────────────────────────────────────────────────────────────
// Activity, attention, notifications
// ─────────────────────────────────────────────────────────────────────────────

export interface ActivityItem {
  id: string
  instanceId?: string
  kind: string
  title: string
  detail?: string
  createdAt: string
  read: boolean
  relatedReceiptId?: string
  route?: string
}

export interface AttentionItem {
  id: string
  instanceId: string
  title: string
  detail: string
  severity: 'info' | 'action_needed' | 'urgent'
  createdAt: string
  read: boolean
  acknowledged: boolean
  actionRoute?: string
}

export interface NotificationItem {
  id: string
  instanceId?: string
  title: string
  body?: string
  importance: 'low' | 'normal' | 'important'
  createdAt: string
  read: boolean
  acknowledged: boolean
  snoozedUntil?: string
  route?: string
  relatedReceiptId?: string
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings
// ─────────────────────────────────────────────────────────────────────────────

export type ThemePreference = 'system' | 'light' | 'dark' | 'high_contrast'
export type Density = 'compact' | 'comfortable'
export type FontScale = 87.5 | 100 | 112.5 | 125

export interface GeneralSettings {
  defaultLandingPage: 'applications' | 'last_workspace'
  reopenLastApplication: boolean
  reopenLastApplicationView: boolean
  dateTimeFormat: 'relative' | 'absolute' | 'both'
  density: Density
  confirmBeforeDestructive: boolean
  defaultApplicationSorting: 'recent' | 'name' | 'manual'
  showRecentApplications: boolean
  restoreWorkspaceLayouts: boolean
  startInFocusMode: boolean
  rememberSearchHistory: boolean
}

export interface AppearanceSettings {
  theme: ThemePreference
  highContrastBase: 'light' | 'dark'
  fontScale: FontScale
  density: Density
  reducedMotion: boolean
  strongerFocusIndicators: boolean
  panelContrast: 'default' | 'increased'
  codeFont: string
  editorTheme: 'match_interface' | 'light' | 'dark'
  terminalTheme: 'match_interface' | 'light' | 'dark'
}

export interface NavigationSettings {
  sidebarDefault: 'expanded' | 'collapsed'
  autoCollapseBelowPx: number
  recentCommands: boolean
  workbenchToolOrder: WorkbenchToolId[]
  restoreLastTool: boolean
  openLinksIn: 'current_view' | 'new_tab'
}

export interface ConversationSettings {
  enterSends: boolean
  draftPersistence: boolean
  showMessageTimestamps: boolean
  compactMessageLayout: boolean
  autoScroll: 'always' | 'when_at_bottom' | 'never'
  confirmBeforeClearingHistory: boolean
  defaultContext: ContextChipKind[]
  showDeliveryDetails: boolean
  toolEventsExpanded: boolean
  soundOnResponseFinished: boolean
}

export interface EditorSettings {
  fontFamily: string
  fontSize: number
  lineHeight: number
  tabSize: number
  indentWith: 'spaces' | 'tabs'
  wordWrap: boolean
  minimap: boolean
  ligatures: boolean
  formatOnSave: boolean
  autoCloseBrackets: boolean
  showWhitespace: boolean
  previewDiffBeforeSave: boolean
  restoreOpenFiles: boolean
  restoreCursorPositions: boolean
  /** Never bypasses governed write review. */
  autosave: boolean
}

export interface TerminalSettings {
  fontFamily: string
  fontSize: number
  lineHeight: number
  cursorStyle: 'block' | 'underline' | 'bar'
  cursorBlink: boolean
  ligatures: boolean
  scrollbackLines: number
  copyOnSelect: boolean
  rightClickBehavior: 'paste' | 'context_menu' | 'select_word'
  multilinePasteConfirmation: boolean
  bell: 'off' | 'visual' | 'sound'
  screenReaderMode: boolean
  linkHandling: 'confirm' | 'open' | 'copy'
  restoreSessionTabs: boolean
  sessionNaming: 'sequential' | 'target_based'
  defaultTargetId?: string
}

export interface NotificationSettings {
  level: 'all' | 'important_only' | 'none'
  approvalAlerts: boolean
  operationCompleteAlerts: boolean
  failureAlerts: boolean
  backupReminders: boolean
  sound: boolean
  quietHours: { enabled: boolean; from: string; to: string }
  /** Per-instance override: instance id → level. */
  applicationOverrides: Record<string, 'all' | 'important_only' | 'none'>
}

export interface PrivacySettings {
  defaultModelContext: ContextChipKind[]
  includeSelectedFilesOnly: boolean
  includeSelectedTerminalOutputOnly: boolean
  diagnosticLogging: boolean
  localTelemetry: boolean
}

export interface AccessibilitySettings {
  fontScale: FontScale
  highContrast: boolean
  reducedMotion: boolean
  strongFocus: boolean
  largerControls: boolean
  screenReaderEnhancements: boolean
  announceOperationProgress: boolean
  terminalScreenReaderMode: boolean
  disableNonessentialAnimation: boolean
}

export interface AdvancedSettings {
  adapterMode: 'mock' | 'http'
  localServiceEndpoint: string
}

export interface GlobalSettings {
  general: GeneralSettings
  appearance: AppearanceSettings
  navigation: NavigationSettings
  conversation: ConversationSettings
  editor: EditorSettings
  terminal: TerminalSettings
  notifications: NotificationSettings
  privacy: PrivacySettings
  accessibility: AccessibilitySettings
  advanced: AdvancedSettings
}

/**
 * One backend-owned global-settings mutation that can be reversed through the
 * exact receipt identity. Browser-only presentation preferences never appear
 * here and are not affected by rollback.
 */
export interface GlobalSettingsRollbackTarget {
  receiptId: string
  revision: number
  action: 'settings.patch' | 'settings.rollback'
  createdAt: string
  changes: Record<string, string | number | boolean>
  previousValues: Record<string, string | number | boolean>
}

/** Bounded rollback history from the current global settings projection. */
export interface GlobalSettingsRollbackHistory {
  currentRevision: number
  targets: GlobalSettingsRollbackTarget[]
}

export interface AppSettings {
  instanceId: string
  notificationLevel: 'inherit' | 'all' | 'important_only' | 'none'
  conversation: {
    defaultContext: ContextChipKind[]
  }
  backup: {
    enabled: boolean
    intervalHours: number
  }
  terminal: {
    defaultTargetId?: string
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Session, service, build
// ─────────────────────────────────────────────────────────────────────────────

export interface SessionInfo {
  authenticated: boolean
  user: { id: string; displayName: string } | null
  issuedAt: string
  expiresAt?: string
}

export type LocalServiceState = 'connected' | 'degraded' | 'offline' | 'unknown'

export interface LocalServiceStatus {
  state: LocalServiceState
  endpoint: string
  version?: string
  lastContactAt?: string
  detail?: string
  /** Installed execution runtime truth (execution-host socket reachability). */
  runtime?: {
    status: 'available' | 'unavailable'
    reason?: string
    detail?: string
    socketPath?: string
    socketPresent?: boolean
    peerPolicy?: string | null
    workerExecutionEnabled?: boolean
  }
  /** Session-derived role metadata; permissions remain backend-enforced. */
  actor?: {
    role: 'local_user' | 'platform_operator'
    actorId: string
    platformOperationsAllowed: boolean
    statebenchInspectionAllowed: boolean
  }
}

export function canInspectPlatformStateBench(status: LocalServiceStatus): boolean {
  return (
    status.actor?.role === 'platform_operator' &&
    status.actor.platformOperationsAllowed === true &&
    status.actor.statebenchInspectionAllowed === true
  )
}

export interface BuildInfo {
  version: string
  commit: string
  builtAt: string
  adapter: 'mock' | 'http'
  mode: 'development' | 'production'
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform deployments, standing authority, installed updater, preview routes
//
// Operator-only host-state projections. Every mutation is digest-bound and
// fails closed when the host has no durable state (`409 *_state_unavailable`)
// or the operator reviews a stale artifact (`409 approval_digest_mismatch`).
// ─────────────────────────────────────────────────────────────────────────────

/** Index row for `GET /v1/deployments` (`stateport.deployment-index/v1`). */
export interface PlatformDeploymentSummary {
  deploymentId: string
  lifecycleState: string
  driftStatus: string | null
  desiredRevision: string | null
  approvedPlanDigest: string | null
  acceptedRevision: string | null
  observedRevision: string | null
  rollback: unknown
  retainedDataState: unknown
  currentOperation: string | null
  serviceHealth: unknown
}

export interface PlatformDeploymentIndex {
  formatVersion: 'stateport.deployment-index/v1'
  deployments: PlatformDeploymentSummary[]
}

/**
 * Full deployment detail (`GET /v1/deployments/{id}`). The backend owns the
 * exact shape; the client preserves it as a passthrough projection so the UI
 * can render observed runtime metadata without inventing a second authority.
 */
export interface PlatformDeploymentDetail {
  state: Record<string, unknown>
}

export interface PlatformDeploymentPlanInput {
  project: string
  deploymentId: string
  grantId: string
  sliceId?: string
  rollbackOf?: string
}

/** Result of `POST /v1/deployments/plan` (and purge/plan). Passthrough. */
export type PlatformDeploymentPlanResult = Record<string, unknown>

/** Result of apply/status/logs/restart/remove. Passthrough (carries receipts). */
export type PlatformDeploymentMutationResult = Record<string, unknown>

/** `GET /v1/authority/profiles` (`stateport.authority-profile-index/v1`). */
export interface AuthorityProfileIndex {
  formatVersion: 'stateport.authority-profile-index/v1'
  schema: string
  defaultProfile: string
  policyDigest: string
  actionPolicies: Record<string, Record<string, unknown>>
  profiles: Record<string, Record<string, unknown>>
  hardDeny: string[]
  mergeRequirements: string[]
  subagentDefaultDeny: string[]
  escalationConditions: unknown[]
}

/** One grant row inside the authority inspect projection. */
export interface AuthorityGrant {
  grantId: string
  grantDigest: string
  [key: string]: unknown
}

/** `GET /v1/authority/grants` — the full inspect projection. Passthrough. */
export interface AuthorityGrantsIndex {
  grants: AuthorityGrant[]
  paused: boolean
  repository?: unknown
  control?: Record<string, unknown>
  recentActions?: unknown[]
  [key: string]: unknown
}

export interface AuthorityIndex {
  schema: 'stateport.authority-index/v1'
  repository: Record<string, unknown>
  policy: AuthorityProfileIndex
  defaultProfile: string
  policyDigest: string
  control: Record<string, unknown> & { paused: boolean; controlDigest: string }
  activeGrants: AuthorityGrant[]
  inactiveGrants: AuthorityGrant[]
  revisions: {
    indexRevision: string
    controlRevision: number
    grantRevisions: Record<string, string>
    [key: string]: unknown
  }
  reviewableDigests: {
    indexDigest: string
    controlDigest: string
    grantDigests: Record<string, string>
    [key: string]: unknown
  }
  recentActions?: unknown[]
  [key: string]: unknown
}

/** `GET /v1/authority/grants/{id}` detail. */
export interface AuthorityGrantDetail {
  grant: AuthorityGrant
  paused: boolean
  repository?: unknown
}

export interface AuthorityRevokeInput {
  ownerDirectiveId: string
  reason: string
  grantDigest: string
}

export interface AuthorityPauseInput {
  paused: boolean
  ownerDirectiveId: string
  reason: string
  controlDigest: string
}

/** `GET /v1/updater/status` — installed updater durable status. Passthrough. */
export type UpdaterStatus = Record<string, unknown>

/** `GET /v1/updater/policy` (`stateport.updater-policy/v1`). */
export interface UpdaterPolicyProjection {
  formatVersion: 'stateport.updater-policy/v1'
  policy: Record<string, unknown>
  statusDigest: string
}

/** `GET /v1/updater/rollback` (`stateport.updater-rollback/v1`). */
export interface UpdaterRollbackProjection {
  formatVersion: 'stateport.updater-rollback/v1'
  phase: string
  pendingPhase: string | null
  retainedPredecessor: Record<string, unknown> | null
  rollbackAvailable: boolean
  statusDigest: string
}

export interface UpdaterPolicyInput {
  policy: Record<string, unknown>
  expectedStatusDigest: string
}

/**
 * Result of `POST /v1/updater/rollback`. The apply boundary is
 * `installed-authority-cli`: applying the staged rollback remains reserved to
 * the installed updater authority boundary and is never exposed over HTTP.
 */
export interface UpdaterRollbackPlanResult {
  plan: Record<string, unknown>
  applyBoundary: 'installed-authority-cli'
  note: string
}

/** One preview route row inside `GET /v1/preview-routes`. */
export interface PreviewRoute {
  schema: 'stateport.preview-route/v1'
  routeId: string
  capsuleId: string
  serviceId: string
  revisionDigest: string
  upstream: { host: string; port: number }
  createdAt: string
  expiresAt: string
  revokedAt: string | null
  revocationReason: string | null
  routeDigest: string
  /** Derived status from the registry (active/expired/revoked). */
  status: 'active' | 'expired' | 'revoked'
}

export interface PreviewRouteReceipt {
  schema: 'stateport.preview-route-receipt/v1'
  receiptId: string
  routeId: string
  sequence: number
  event: 'registered' | 'rewritten' | 'revoked'
  actor: string
  createdAt: string
  data: Record<string, unknown>
  previousReceiptDigest: string | null
  receiptDigest: string
}

export interface PreviewRouteMutation extends PreviewRoute {
  receipt: PreviewRouteReceipt
}

export interface PreviewRouteIndex {
  routes: PreviewRoute[]
  /**
   * Typed availability of the preview surface. Same-origin previews are
   * disabled for security until a credential-isolated origin exists; when
   * disabled the service explains why and `routes` is empty.
   */
  availability?: {
    status: 'enabled' | 'disabled'
    code?: string
    message?: string
    nextAction?: string
  }
}

export interface PreviewRouteRegisterInput {
  capsuleId: string
  serviceId: string
  revisionDigest: string
  upstreamPort: number
  ttlSeconds: number
}

export interface PreviewRouteRewriteInput {
  revisionDigest: string
  upstreamPort: number
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

export type ClientErrorKind =
  | 'network'
  | 'http'
  | 'validation'
  | 'unavailable'
  | 'not_implemented'

export class ClientError extends Error {
  readonly kind: ClientErrorKind
  readonly status?: number
  /** Machine-readable detail for diagnostics drawers. */
  readonly detail?: string
  /**
   * Stable machine-readable error code (e.g. `FILE_WORKBENCH_ADAPTER_REQUIRED`),
   * when the failure carries one. Additive — older throws leave it undefined.
   */
  readonly code?: string

  constructor(
    kind: ClientErrorKind,
    message: string,
    options?: { status?: number; detail?: string; code?: string },
  ) {
    super(message)
    this.name = 'ClientError'
    this.kind = kind
    this.status = options?.status
    this.detail = options?.detail
    this.code = options?.code
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// List filters
// ─────────────────────────────────────────────────────────────────────────────

export interface ReceiptFilter {
  instanceId?: string
  query?: string
  result?: ReceiptResult
  eventKind?: string
  limit?: number
  /**
   * Caller-supplied capability knowledge. Pass `false` when the instance
   * projection already shows no effective goal-execution (CTO) capability:
   * the list then skips the goal-execution projection poll the service must
   * refuse fail-closed (403). Undefined keeps the default poll-and-tolerate
   * behavior for callers that do not know the capability state.
   */
  goalExecution?: boolean
}

export interface ApprovalFilter {
  instanceId?: string
  status?: ApprovalStatus
  risk?: RiskLevel
  query?: string
}

export interface ActivityFilter {
  instanceId?: string
  unreadOnly?: boolean
  limit?: number
}
