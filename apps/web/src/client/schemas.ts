/**
 * Zod schemas for every response type that crosses the adapter boundary.
 *
 * Both adapters validate at runtime: the mock validates its own persisted
 * state on load (corruption ⇒ reseed), the HTTP adapter validates every
 * response. Schemas and static types are kept in lockstep via the
 * `Exact<…>` assertions at the bottom of this file.
 */
import { z } from 'zod'

import type {
  ActivityItem,
  ApplicationInstance,
  ApplicationPackage,
  Approval,
  AppSettings,
  Attachment,
  AttentionItem,
  AuthorizationGrant,
  BuildInfo,
  CapabilityState,
  CatalogPackage,
  ContextChip,
  Conversation,
  ConversationMessage,
  FileChange,
  FileDiff,
  FileEntry,
  FileNode,
  GlobalSettings,
  InfrastructurePlan,
  InfrastructureTarget,
  LocalServiceStatus,
  NotificationItem,
  OperationRecord,
  OrchestrationSession,
  PlatformStateBenchView,
  Receipt,
  ResolvedApplicationExperience,
  RunStatus,
  SessionInfo,
  TerminalSession,
  TerminalTarget,
  ToolEvent,
} from './types'

const iso = z.iso.datetime()

const planDigestSchema = z.object({
  algorithm: z.literal('sha256'),
  value: z.string().min(8),
})

const runStatusSchema = z.enum([
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

const platformStateBenchDegradationSchema = z
  .object({
    id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
    status: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/).optional(),
  })
  .strict()

const platformStateBenchRowSchema = z
  .object({
    formatVersion: z.literal('statebench.run-bundle-row/v1'),
    integrityStatus: z.literal('verified'),
    authoritative: z.literal(false),
    producerClaimsTrusted: z.literal(false),
    bundleDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    runId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
    applicationId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
    engineId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
    adapterId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
    status: runStatusSchema,
    statePreserved: z.boolean(),
    capabilityDegradations: z.array(platformStateBenchDegradationSchema).max(64),
    acceptedRun: z.boolean(),
    usageAvailable: z.boolean().nullable(),
    latencyMs: z.number().finite().min(0).max(86_400_000).nullable(),
    unauthorizedMutations: z.number().int().min(0).max(1_000_000),
    bundleFileCount: z.number().int().min(0).max(1024),
  })
  .strict()

const platformStateBenchViewSchema = z
  .object({
    formatVersion: z.literal('stateport.platform-statebench-view/v1'),
    rows: z.array(platformStateBenchRowSchema).max(100),
    verifiedRowCount: z.number().int().nonnegative(),
    rejectedOrUnverifiedCount: z.number().int().nonnegative(),
    truncated: z.boolean(),
    hardOutcomeOnly: z.literal(true),
    authoritativePerformanceClaim: z.literal(false),
    calibrationMeaning: z.literal(
      'Harness behavior only; comparative performance is not established.',
    ),
  })
  .strict()

const semanticStateSchema = z.enum([
  'success',
  'neutral',
  'attention',
  'waiting',
  'blocked',
  'danger',
  'informational',
])

const operationStateSchema = z.enum([
  'draft',
  'proposed',
  'preparing',
  'prepared',
  'awaiting_approval',
  'approved',
  'queued',
  'running',
  'completed',
  'cancelling',
  'paused',
  'interrupted',
  'applied',
  'validating',
  'validated',
  'completed_without_change',
  'rejected',
  'cancelled',
  'blocked',
  'unavailable',
  'failed',
  'human_accepted',
])

const capabilityIdSchema = z.enum([
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
])

const capabilityStateSchema = z.object({
  id: capabilityIdSchema,
  status: z.enum(['available', 'degraded', 'environment_gated', 'unavailable']),
  reason: z.string().optional(),
})

const applicationExperienceComponentSchema = z.enum([
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

const resolvedApplicationExperienceSchema = z.object({
  formatVersion: z.literal('stateport.application-experience-resolution/v1'),
  applicationId: z.string(),
  descriptorDigest: planDigestSchema.optional(),
  views: z.array(z.object({
    viewId: z.string(),
    label: z.string(),
    component: applicationExperienceComponentSchema,
    declaredRoute: z.string(),
    capability: capabilityIdSchema,
    status: z.enum(['available', 'degraded', 'environment_gated', 'unavailable']),
    reasons: z.array(z.string()),
    visible: z.boolean(),
  })),
  navigation: z.array(z.object({
    contributionId: z.string(),
    label: z.string(),
    viewId: z.string(),
    placement: z.enum(['application', 'conversation', 'advanced']),
    order: z.number().int().min(0).max(1000),
    visible: z.boolean(),
  })),
  advancedControls: z.array(z.object({
    controlId: z.string(),
    label: z.string(),
    component: applicationExperienceComponentSchema,
    capability: capabilityIdSchema,
    order: z.number().int().min(0).max(1000),
    status: z.enum(['available', 'degraded', 'environment_gated', 'unavailable']),
    reasons: z.array(z.string()),
    visible: z.boolean(),
  })),
})

const workbenchToolIdSchema = z.enum([
  'overview',
  'files',
  'terminal',
  'deployments',
  'orchestration',
  'receipts',
])

const packagePermissionsSchema = z.object({
  fileAccess: z.string(),
  terminalAccess: z.string(),
  networkAccess: z.string(),
  dataOwnership: z.string(),
})

const applicationPackageSchema = z.object({
  id: z.string(),
  name: z.string(),
  displayName: z.string(),
  description: z.string(),
  version: z.string(),
  releaseStatus: z.enum(['stable', 'beta', 'experimental']),
  reviewClassification: z.enum(['reviewed', 'community']),
  capabilities: z.array(capabilityIdSchema),
  views: z.array(z.string()),
  permissions: packagePermissionsSchema,
  networkPolicy: z.enum(['none', 'local_only', 'restricted', 'full']),
  dataBoundaries: z.array(z.string()),
  workbenchTools: z.array(workbenchToolIdSchema),
  productionEligible: z.boolean().optional(),
  publicSafe: z.boolean().optional(),
  sourceKind: z.string().optional(),
  privacyClassification: z.string().optional(),
})

const repositoryIdentitySchema = z.object({
  name: z.string(),
  branch: z.string(),
  revision: z.string(),
  clean: z.boolean(),
})

const applicationSourceIdentitySchema = z.object({
  templateId: z.string().optional(),
  repository: z.string().optional(),
  resolvedCommit: z.string().optional(),
  resolvedTree: z.string().optional(),
  manifestDigest: z.string().optional(),
  sourceDigest: z.string().optional(),
  sourceKind: z.string().optional(),
  sourceClass: z.string().optional(),
  sourceAccessClass: z.enum(['canonical_release', 'development_candidate']).optional(),
  ownership: z.string().optional(),
  version: z.string().optional(),
  productionEligible: z.boolean().optional(),
  productionInstallAllowed: z.boolean().optional(),
  compatibilityRevision: z.string().optional(),
  compatibilityTree: z.string().optional(),
})

const applicationOwnershipRecordSchema = z.object({
  template: z.number().int().nonnegative(),
  instance: z.number().int().nonnegative(),
  generated: z.number().int().nonnegative(),
  override: z.number().int().nonnegative(),
})

const applicationOwnershipPathsSchema = z.object({
  template: z.array(z.string()),
  instance: z.array(z.string()),
  generated: z.array(z.string()),
  override: z.array(z.string()),
})

const applicationOwnershipTruncatedSchema = z.object({
  template: z.boolean(),
  instance: z.boolean(),
  generated: z.boolean(),
  override: z.boolean(),
})

const applicationProvenanceSchema = z.object({
  source: applicationSourceIdentitySchema,
  ownership: z.object({
    counts: applicationOwnershipRecordSchema,
    paths: applicationOwnershipPathsSchema,
    truncated: applicationOwnershipTruncatedSchema,
  }).optional(),
})

const activityItemSchema = z.object({
  id: z.string(),
  instanceId: z.string().optional(),
  kind: z.string(),
  title: z.string(),
  detail: z.string().optional(),
  createdAt: iso,
  read: z.boolean(),
  relatedReceiptId: z.string().optional(),
  route: z.string().optional(),
})

const attentionItemSchema = z.object({
  id: z.string(),
  instanceId: z.string(),
  title: z.string(),
  detail: z.string(),
  severity: z.enum(['info', 'action_needed', 'urgent']),
  createdAt: iso,
  read: z.boolean(),
  acknowledged: z.boolean(),
  actionRoute: z.string().optional(),
})

const contextChipKindSchema = z.enum([
  'application',
  'file',
  'selection',
  'terminal',
  'plan',
  'approval',
  'receipt',
  'summary',
])

const appSettingsSchema = z.object({
  instanceId: z.string(),
  notificationLevel: z.enum(['inherit', 'all', 'important_only', 'none']),
  conversation: z.object({ defaultContext: z.array(contextChipKindSchema) }),
  backup: z.object({ enabled: z.boolean(), intervalHours: z.number() }),
  terminal: z.object({ defaultTargetId: z.string().optional() }),
})

const recoveryInfoSchema = z.object({
  state: z.enum(['current', 'due', 'running', 'failed', 'not_configured']),
  lastBackupAt: iso.optional(),
  nextDueAt: iso.optional(),
  lastReceiptId: z.string().optional(),
  detail: z.string().optional(),
})

const packageStateDataSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('study-state'),
    goal: z.string(),
    goalProgressPercent: z.number().min(0).max(100),
    activities: z.array(
      z.object({
        id: z.string(),
        title: z.string(),
        reason: z.string().optional(),
        state: z.enum(['not_started', 'in_progress', 'paused', 'done']),
        updatedAt: iso,
      }),
    ),
    evidence: z.array(
      z.object({
        id: z.string(),
        title: z.string(),
        state: z.enum(['missing', 'draft', 'self_reported', 'verified']),
        updatedAt: iso,
      }),
    ),
    planDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/).optional(),
    canUndo: z.boolean().optional(),
    lastTransition: z.record(z.string(), z.unknown()).optional(),
  }),
  z.object({
    kind: z.literal('checklist-state'),
    items: z.array(
      z.object({ id: z.string(), title: z.string(), done: z.boolean(), updatedAt: iso }),
    ),
  }),
])

const applicationInstanceSchema = z.object({
  id: z.string(),
  name: z.string(),
  packageId: z.string(),
  packageName: z.string(),
  packageDisplayName: z.string(),
  health: z.enum(['ready', 'attention_needed', 'degraded', 'blocked', 'offline']),
  attention: z.array(attentionItemSchema),
  recentActivity: z.array(activityItemSchema),
  settings: appSettingsSchema,
  conversationId: z.string().optional(),
  capabilities: z.array(capabilityStateSchema),
  experience: resolvedApplicationExperienceSchema.optional(),
  experienceResolution: z.enum(['resolved', 'unavailable']).optional(),
  receiptIds: z.array(z.string()),
  recovery: recoveryInfoSchema,
  repository: repositoryIdentitySchema.optional(),
  provenance: applicationProvenanceSchema.optional(),
  runtimeIdentity: z.string().optional(),
  packageState: packageStateDataSchema.optional(),
  pinned: z.boolean(),
  createdAt: iso,
  lastOpenedAt: iso.optional(),
})

const catalogPackageSchema = z.object({
  pkg: applicationPackageSchema,
  installedInstanceCount: z.number().int().nonnegative(),
  updateAvailable: z
    .object({ fromVersion: z.string(), toVersion: z.string(), releaseNotes: z.string() })
    .optional(),
  installRequiresApproval: z.boolean(),
})

const attachmentSchema = z.object({
  id: z.string(),
  name: z.string(),
  mimeType: z.string(),
  sizeBytes: z.number().int().nonnegative(),
  state: z.enum(['uploading', 'ready', 'failed']),
  progress: z.number().min(0).max(100).optional(),
  error: z.string().optional(),
  retentionNote: z.string().optional(),
})

const contextChipSchema = z.object({
  id: z.string(),
  kind: contextChipKindSchema,
  label: z.string(),
  refId: z.string().optional(),
  detail: z.string().optional(),
  removable: z.boolean(),
})

const toolEventSchema = z.object({
  id: z.string(),
  kind: z.string(),
  summary: z.string(),
  detail: z.string().optional(),
  state: operationStateSchema,
  createdAt: iso,
})

const conversationMessageSchema = z.object({
  id: z.string(),
  conversationId: z.string(),
  role: z.enum(['user', 'assistant', 'system']),
  content: z.string(),
  createdAt: iso,
  state: z.enum(['complete', 'streaming', 'stopped', 'failed']),
  attachments: z.array(attachmentSchema),
  contextChips: z.array(contextChipSchema),
  toolEvents: z.array(toolEventSchema),
  proposal: z
    .object({ title: z.string(), detail: z.string(), actionRoute: z.string().optional() })
    .optional(),
})

const conversationSchema = z.object({
  id: z.string(),
  instanceId: z.string(),
  title: z.string(),
  channel: z.enum(['web', 'telegram']),
  deliveryState: z.enum(['delivered', 'pending', 'failed', 'not_configured']),
  retentionNote: z.string(),
  messages: z.array(conversationMessageSchema),
  createdAt: iso,
  updatedAt: iso,
})

const fileNodeSchema: z.ZodType<FileNode> = z.lazy(() =>
  z.object({
    path: z.string(),
    name: z.string(),
    kind: z.enum(['file', 'directory']),
    sizeBytes: z.number().optional(),
    modifiedAt: iso.optional(),
    readOnly: z.boolean().optional(),
    gitStatus: z.enum(['clean', 'modified', 'untracked', 'locked']).optional(),
    children: z.array(fileNodeSchema).optional(),
  }),
)

const fileEntrySchema = z.object({
  path: z.string(),
  content: z.string(),
  revision: z.string(),
  readOnly: z.boolean(),
  encoding: z.literal('utf-8'),
  modifiedAt: iso,
})

const fileDiffSchema = z.object({
  unified: z.string(),
  addedLines: z.number().int().nonnegative(),
  removedLines: z.number().int().nonnegative(),
})

const fileChangeSchema = z.object({
  id: z.string(),
  instanceId: z.string(),
  path: z.string(),
  beforeRevision: z.string(),
  afterRevision: z.string(),
  diff: fileDiffSchema,
  createdAt: iso,
})

const writeFileResultSchema = z.discriminatedUnion('ok', [
  z.object({ ok: z.literal(true), change: fileChangeSchema, receipt: z.lazy(() => receiptSchema), entry: fileEntrySchema }),
  z.object({
    ok: z.literal(false),
    reason: z.enum(['conflict', 'path_policy', 'read_only', 'validation']),
    detail: z.string(),
    currentRevision: z.string().optional(),
    currentContent: z.string().optional(),
  }),
])

const terminalTargetSchema = z.object({
  id: z.string(),
  instanceId: z.string(),
  label: z.string(),
  kind: z.enum(['local_pty', 'ssh']),
  available: z.boolean(),
  unavailableReason: z.string().optional(),
})

const terminalSessionSchema = z.object({
  id: z.string(),
  targetId: z.string(),
  instanceId: z.string(),
  name: z.string(),
  state: z.enum(['idle', 'connecting', 'connected', 'reconnecting', 'failed', 'ended']),
  cwd: z.string(),
  createdAt: iso,
  lastError: z.string().optional(),
})

const infrastructureTargetSchema = z.object({
  id: z.string(),
  instanceId: z.string(),
  name: z.string(),
  kind: z.literal('local_vm'),
  available: z.boolean(),
  unavailableReason: z.string().optional(),
  repository: repositoryIdentitySchema,
  vm: z.object({
    state: z.enum(['not_defined', 'stopped', 'starting', 'running', 'stopping', 'unavailable']),
    since: iso.optional(),
  }),
  ssh: z.object({
    state: z.enum(['not_checked', 'ready', 'unavailable_vm_not_defined', 'unavailable_vm_stopped', 'failed']),
    detail: z.string().optional(),
  }),
  health: z.object({
    state: z.enum(['not_checked', 'checking', 'healthy', 'unhealthy', 'unavailable']),
    checkedAt: iso.optional(),
    detail: z.string().optional(),
  }),
})

const planStepSchema = z.object({
  id: z.string(),
  title: z.string(),
  detail: z.string(),
  kind: z.enum(['command', 'check', 'gate']),
})

const infrastructureOperationSchema = z.enum([
  'observe',
  'validate',
  'health_check',
  'create_or_update',
  'start',
  'stop',
  'restart',
  'destroy',
])

const infrastructurePlanSchema = z.object({
  id: z.string(),
  instanceId: z.string(),
  targetId: z.string(),
  operation: infrastructureOperationSchema,
  title: z.string(),
  state: operationStateSchema,
  risk: z.enum(['low', 'medium', 'high']),
  requiresApproval: z.boolean(),
  coveredByAuthorization: z.boolean(),
  steps: z.array(planStepSchema),
  digest: planDigestSchema,
  beforeSummary: z.string(),
  afterSummary: z.string(),
  rollbackNotes: z.string(),
  approvalId: z.string().optional(),
  receiptId: z.string().optional(),
  createdAt: iso,
})

const authorizationGrantSchema = z.object({
  id: z.string(),
  instanceId: z.string(),
  targetId: z.string(),
  status: z.enum(['proposed', 'active', 'expired', 'revoked']),
  covers: z.array(infrastructureOperationSchema),
  doesNotCover: z.array(z.string()),
  createdAt: iso,
  expiresAt: iso.optional(),
  createdByReceiptId: z.string().optional(),
  revokedAt: iso.optional(),
  revokeReceiptId: z.string().optional(),
})

const approvalDecisionSchema = z.object({
  kind: z.enum(['run_approval', 'run_proposal', 'infrastructure_plan', 'authorization_grant', 'goal_execution', 'template_upgrade']),
  expectedInstanceId: z.string(),
  expectedRevision: z.number().int().nonnegative().optional(),
  expectedDigest: z.string(),
})

const approvalSchema = z.object({
  id: z.string(),
  instanceId: z.string(),
  kind: z.enum(['infrastructure_plan', 'orchestration_run', 'authorization_grant', 'goal_execution', 'template_upgrade', 'file_write', 'capability_change']),
  title: z.string(),
  operationType: z.string(),
  risk: z.enum(['low', 'medium', 'high']),
  status: z.enum(['pending', 'approved', 'rejected', 'expired']),
  scope: z.array(z.string()),
  beforeSummary: z.string(),
  afterSummary: z.string(),
  diff: fileDiffSchema.optional(),
  planDigest: planDigestSchema,
  planId: z.string().optional(),
  targetId: z.string().optional(),
  runId: z.string().optional(),
  whyRequired: z.string(),
  requestedAt: iso,
  expiresAt: iso.optional(),
  decision: approvalDecisionSchema,
  currentDigest: planDigestSchema.optional(),
  decidedAt: iso.optional(),
  decisionReason: z.string().optional(),
  resultingReceiptId: z.string().optional(),
  relatedConversationId: z.string().optional(),
}).superRefine((approval, context) => {
  const templateKind = approval.kind === 'template_upgrade'
  const templateDecision = approval.decision.kind === 'template_upgrade'
  if (templateKind !== templateDecision) {
    context.addIssue({
      code: 'custom',
      path: ['decision', 'kind'],
      message: 'template upgrade presentation and decision authorities must match',
    })
  }
  if ((templateKind || templateDecision) && !approval.targetId) {
    context.addIssue({
      code: 'custom',
      path: ['targetId'],
      message: 'template upgrade approvals require an exact operation identity',
    })
  }
})

const receiptResultSchema = z.enum([
  'approved',
  'applied',
  'executed',
  'completed',
  'validated',
  'completed_without_change',
  'rejected',
  'cancelled',
  'failed',
  'human_accepted',
])

const receiptSchema = z.object({
  id: z.string(),
  instanceId: z.string(),
  packageId: z.string(),
  actionName: z.string(),
  eventKind: z.string(),
  actor: z.enum(['user', 'assistant', 'system']),
  result: receiptResultSchema,
  createdAt: iso,
  expectedRevision: z.string().optional(),
  resultRevision: z.string().optional(),
  planDigest: planDigestSchema.optional(),
  payloadDigest: planDigestSchema.optional(),
  validation: z.object({
    state: z.enum(['not_recorded', 'not_required', 'validating', 'validated', 'failed']),
    detail: z.string(),
  }),
  summary: z.string(),
  beforeSummary: z.string().optional(),
  afterSummary: z.string().optional(),
  diff: fileDiffSchema.optional(),
  relatedOperationId: z.string().optional(),
  relatedConversationId: z.string().optional(),
  relatedApprovalId: z.string().optional(),
  relatedPlanId: z.string().optional(),
  rawJson: z.string(),
})

const operationRecordSchema = z.object({
  id: z.string(),
  instanceId: z.string(),
  kind: z.enum(['infrastructure_plan', 'orchestration_run', 'backup', 'export']),
  title: z.string(),
  state: operationStateSchema,
  stageLabel: z.string(),
  progressPercent: z.number().min(0).max(100).optional(),
  startedAt: iso,
  updatedAt: iso,
  canPause: z.boolean(),
  canCancel: z.boolean(),
  log: z.array(z.string()),
  relatedPlanId: z.string().optional(),
  relatedReceiptId: z.string().optional(),
  error: z.string().optional(),
})

const orchestrationSessionSchema = z.object({
  id: z.string(),
  instanceId: z.string(),
  objective: z.string(),
  mode: z.enum(['advisory', 'assisted', 'managed_approved_queue', 'off']),
  stage: z.enum([
    'enter_objective',
    'select_mode',
    'prepare_slice',
    'review_base',
    'review_plan',
    'review_permissions',
    'review_budget',
    'approve',
    'run',
    'review_result',
    'independent_review',
    'close',
    'receipt',
  ]),
  state: operationStateSchema,
  baseIdentity: repositoryIdentitySchema,
  scope: z.array(z.string()),
  permissions: z.array(z.string()),
  budget: z.object({
    maxOperations: z.number(),
    maxMinutes: z.number(),
    usedOperations: z.number(),
    usedMinutes: z.number(),
  }),
  implementer: z.string(),
  reviewer: z.string(),
  resultSummary: z.string().optional(),
  receiptId: z.string().optional(),
  createdAt: iso,
  updatedAt: iso,
})

const notificationItemSchema = z.object({
  id: z.string(),
  instanceId: z.string().optional(),
  title: z.string(),
  body: z.string().optional(),
  importance: z.enum(['low', 'normal', 'important']),
  createdAt: iso,
  read: z.boolean(),
  acknowledged: z.boolean(),
  snoozedUntil: iso.optional(),
  route: z.string().optional(),
  relatedReceiptId: z.string().optional(),
})

const fontScaleSchema = z.union([z.literal(87.5), z.literal(100), z.literal(112.5), z.literal(125)])
const densitySchema = z.enum(['compact', 'comfortable'])

const globalSettingsSchema = z.object({
  general: z.object({
    defaultLandingPage: z.enum(['applications', 'last_workspace']),
    reopenLastApplication: z.boolean(),
    reopenLastApplicationView: z.boolean(),
    dateTimeFormat: z.enum(['relative', 'absolute', 'both']),
    density: densitySchema,
    confirmBeforeDestructive: z.boolean(),
    defaultApplicationSorting: z.enum(['recent', 'name', 'manual']),
    showRecentApplications: z.boolean(),
    restoreWorkspaceLayouts: z.boolean(),
    startInFocusMode: z.boolean(),
    rememberSearchHistory: z.boolean(),
  }),
  appearance: z.object({
    theme: z.enum(['system', 'light', 'dark', 'high_contrast']),
    highContrastBase: z.enum(['light', 'dark']),
    fontScale: fontScaleSchema,
    density: densitySchema,
    reducedMotion: z.boolean(),
    strongerFocusIndicators: z.boolean(),
    panelContrast: z.enum(['default', 'increased']),
    codeFont: z.string(),
    editorTheme: z.enum(['match_interface', 'light', 'dark']),
    terminalTheme: z.enum(['match_interface', 'light', 'dark']),
  }),
  navigation: z.object({
    sidebarDefault: z.enum(['expanded', 'collapsed']),
    autoCollapseBelowPx: z.number(),
    recentCommands: z.boolean(),
    workbenchToolOrder: z.array(workbenchToolIdSchema),
    restoreLastTool: z.boolean(),
    openLinksIn: z.enum(['current_view', 'new_tab']),
  }),
  conversation: z.object({
    enterSends: z.boolean(),
    draftPersistence: z.boolean(),
    showMessageTimestamps: z.boolean(),
    compactMessageLayout: z.boolean(),
    autoScroll: z.enum(['always', 'when_at_bottom', 'never']),
    confirmBeforeClearingHistory: z.boolean(),
    defaultContext: z.array(contextChipKindSchema),
    showDeliveryDetails: z.boolean(),
    toolEventsExpanded: z.boolean(),
    soundOnResponseFinished: z.boolean(),
  }),
  editor: z.object({
    fontFamily: z.string(),
    fontSize: z.number(),
    lineHeight: z.number(),
    tabSize: z.number(),
    indentWith: z.enum(['spaces', 'tabs']),
    wordWrap: z.boolean(),
    minimap: z.boolean(),
    ligatures: z.boolean(),
    formatOnSave: z.boolean(),
    autoCloseBrackets: z.boolean(),
    showWhitespace: z.boolean(),
    previewDiffBeforeSave: z.boolean(),
    restoreOpenFiles: z.boolean(),
    restoreCursorPositions: z.boolean(),
    autosave: z.boolean(),
  }),
  terminal: z.object({
    fontFamily: z.string(),
    fontSize: z.number(),
    lineHeight: z.number(),
    cursorStyle: z.enum(['block', 'underline', 'bar']),
    cursorBlink: z.boolean(),
    ligatures: z.boolean(),
    scrollbackLines: z.number(),
    copyOnSelect: z.boolean(),
    rightClickBehavior: z.enum(['paste', 'context_menu', 'select_word']),
    multilinePasteConfirmation: z.boolean(),
    bell: z.enum(['off', 'visual', 'sound']),
    screenReaderMode: z.boolean(),
    linkHandling: z.enum(['confirm', 'open', 'copy']),
    restoreSessionTabs: z.boolean(),
    sessionNaming: z.enum(['sequential', 'target_based']),
    defaultTargetId: z.string().optional(),
  }),
  notifications: z.object({
    level: z.enum(['all', 'important_only', 'none']),
    approvalAlerts: z.boolean(),
    operationCompleteAlerts: z.boolean(),
    failureAlerts: z.boolean(),
    backupReminders: z.boolean(),
    sound: z.boolean(),
    quietHours: z.object({ enabled: z.boolean(), from: z.string(), to: z.string() }),
    applicationOverrides: z.record(z.string(), z.enum(['all', 'important_only', 'none'])),
  }),
  privacy: z.object({
    defaultModelContext: z.array(contextChipKindSchema),
    includeSelectedFilesOnly: z.boolean(),
    includeSelectedTerminalOutputOnly: z.boolean(),
    diagnosticLogging: z.boolean(),
    localTelemetry: z.boolean(),
  }),
  accessibility: z.object({
    fontScale: fontScaleSchema,
    highContrast: z.boolean(),
    reducedMotion: z.boolean(),
    strongFocus: z.boolean(),
    largerControls: z.boolean(),
    screenReaderEnhancements: z.boolean(),
    announceOperationProgress: z.boolean(),
    terminalScreenReaderMode: z.boolean(),
    disableNonessentialAnimation: z.boolean(),
  }),
  advanced: z.object({
    adapterMode: z.enum(['mock', 'http']),
    localServiceEndpoint: z.string(),
  }),
})

const sessionInfoSchema = z.object({
  authenticated: z.boolean(),
  user: z.object({ id: z.string(), displayName: z.string() }).nullable(),
  issuedAt: iso,
  expiresAt: iso.optional(),
})

const localServiceStatusSchema = z.object({
  state: z.enum(['connected', 'degraded', 'offline', 'unknown']),
  endpoint: z.string(),
  version: z.string().optional(),
  lastContactAt: iso.optional(),
  detail: z.string().optional(),
})

const buildInfoSchema = z.object({
  version: z.string(),
  commit: z.string(),
  builtAt: iso,
  adapter: z.enum(['mock', 'http']),
  mode: z.enum(['development', 'production']),
})

export const schemas = {
  activityItem: activityItemSchema,
  applicationInstance: applicationInstanceSchema,
  applicationPackage: applicationPackageSchema,
  approval: approvalSchema,
  appSettings: appSettingsSchema,
  attachment: attachmentSchema,
  attentionItem: attentionItemSchema,
  authorizationGrant: authorizationGrantSchema,
  buildInfo: buildInfoSchema,
  capabilityState: capabilityStateSchema,
  catalogPackage: catalogPackageSchema,
  contextChip: contextChipSchema,
  conversation: conversationSchema,
  conversationMessage: conversationMessageSchema,
  fileChange: fileChangeSchema,
  fileDiff: fileDiffSchema,
  fileEntry: fileEntrySchema,
  fileNode: fileNodeSchema,
  globalSettings: globalSettingsSchema,
  infrastructurePlan: infrastructurePlanSchema,
  infrastructureTarget: infrastructureTargetSchema,
  localServiceStatus: localServiceStatusSchema,
  notificationItem: notificationItemSchema,
  operationRecord: operationRecordSchema,
  operationState: operationStateSchema,
  orchestrationSession: orchestrationSessionSchema,
  planDigest: planDigestSchema,
  platformStateBenchView: platformStateBenchViewSchema,
  receipt: receiptSchema,
  resolvedApplicationExperience: resolvedApplicationExperienceSchema,
  semanticState: semanticStateSchema,
  sessionInfo: sessionInfoSchema,
  terminalSession: terminalSessionSchema,
  terminalTarget: terminalTargetSchema,
  writeFileResult: writeFileResultSchema,
} as const

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time schema ↔ type alignment assertions.
// If a schema and its static type drift apart, this file stops compiling.
// ─────────────────────────────────────────────────────────────────────────────

type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never
type Assert<T extends true> = T

export type _SchemaTypeChecks = [
  Assert<Exact<z.infer<typeof applicationInstanceSchema>, ApplicationInstance>>,
  Assert<Exact<z.infer<typeof applicationPackageSchema>, ApplicationPackage>>,
  Assert<Exact<z.infer<typeof catalogPackageSchema>, CatalogPackage>>,
  Assert<Exact<z.infer<typeof approvalSchema>, Approval>>,
  Assert<Exact<z.infer<typeof appSettingsSchema>, AppSettings>>,
  Assert<Exact<z.infer<typeof attachmentSchema>, Attachment>>,
  Assert<Exact<z.infer<typeof attentionItemSchema>, AttentionItem>>,
  Assert<Exact<z.infer<typeof authorizationGrantSchema>, AuthorizationGrant>>,
  Assert<Exact<z.infer<typeof buildInfoSchema>, BuildInfo>>,
  Assert<Exact<z.infer<typeof capabilityStateSchema>, CapabilityState>>,
  Assert<Exact<z.infer<typeof contextChipSchema>, ContextChip>>,
  Assert<Exact<z.infer<typeof conversationSchema>, Conversation>>,
  Assert<Exact<z.infer<typeof conversationMessageSchema>, ConversationMessage>>,
  Assert<Exact<z.infer<typeof fileChangeSchema>, FileChange>>,
  Assert<Exact<z.infer<typeof fileDiffSchema>, FileDiff>>,
  Assert<Exact<z.infer<typeof fileEntrySchema>, FileEntry>>,
  Assert<Exact<z.infer<typeof globalSettingsSchema>, GlobalSettings>>,
  Assert<Exact<z.infer<typeof infrastructurePlanSchema>, InfrastructurePlan>>,
  Assert<Exact<z.infer<typeof infrastructureTargetSchema>, InfrastructureTarget>>,
  Assert<Exact<z.infer<typeof localServiceStatusSchema>, LocalServiceStatus>>,
  Assert<Exact<z.infer<typeof notificationItemSchema>, NotificationItem>>,
  Assert<Exact<z.infer<typeof operationRecordSchema>, OperationRecord>>,
  Assert<Exact<z.infer<typeof orchestrationSessionSchema>, OrchestrationSession>>,
  Assert<Exact<z.infer<typeof platformStateBenchViewSchema>, PlatformStateBenchView>>,
  Assert<Exact<z.infer<typeof receiptSchema>, Receipt>>,
  Assert<Exact<z.infer<typeof resolvedApplicationExperienceSchema>, ResolvedApplicationExperience>>,
  Assert<Exact<z.infer<typeof sessionInfoSchema>, SessionInfo>>,
  Assert<Exact<z.infer<typeof terminalSessionSchema>, TerminalSession>>,
  Assert<Exact<z.infer<typeof terminalTargetSchema>, TerminalTarget>>,
  Assert<Exact<z.infer<typeof toolEventSchema>, ToolEvent>>,
  Assert<Exact<z.infer<typeof activityItemSchema>, ActivityItem>>,
  Assert<Exact<z.infer<typeof runStatusSchema>, RunStatus>>,
]
