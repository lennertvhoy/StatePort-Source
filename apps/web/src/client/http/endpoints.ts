/**
 * Centralized StatePort backend endpoint paths (contract §14 — binding).
 *
 * Every production path lives here and ONLY here; domain clients never build
 * path strings inline. Do not invent new production endpoints — when a
 * frontend feature has no contract endpoint, the domain client fails closed
 * with ClientError 'unavailable' instead.
 */

const enc = encodeURIComponent

export const endpoints = {
  // ── Session and platform ──────────────────────────────────────────────────
  session: '/session',
  status: '/v1/status',
  platformStateBench: '/v1/platform/statebench',

  // ── Catalog, applications, sources, instances ─────────────────────────────
  applicationExperiences: '/v1/application-experiences',
  applications: '/v1/applications',
  sources: '/v1/sources',
  source: (sourceId: string) => `/v1/sources/${enc(sourceId)}`,
  sourceDevelopmentResolve: (sourceId: string) => `/v1/sources/${enc(sourceId)}/development-resolve`,
  instances: '/v1/instances',
  instance: (instanceId: string) => `/v1/instances/${enc(instanceId)}`,
  instanceExperience: (instanceId: string) => `/v1/instances/${enc(instanceId)}/experience`,
  catalogRefresh: '/v1/catalog/refresh',
  applicationFixtureInstall: '/v1/application-fixtures/install',

  // ── Local repository registration ─────────────────────────────────────────
  repositoryImportLocalCandidates: '/v1/repository-import/local-candidates',
  repositoryImportInspect: '/v1/repository-import/inspect',
  repositoryImportRegister: '/v1/repository-import/register',

  // ── Global settings ───────────────────────────────────────────────────────
  settings: '/v1/settings',
  settingsRollback: '/v1/settings/rollback',

  // ── Application settings ──────────────────────────────────────────────────
  appSettings: (instanceId: string) => `/v1/instances/${enc(instanceId)}/settings`,
  appSettingsRollback: (instanceId: string) => `/v1/instances/${enc(instanceId)}/settings-rollback`,

  // ── Activity and attention ────────────────────────────────────────────────
  activity: (instanceId: string) => `/v1/instances/${enc(instanceId)}/activity`,
  attentionRead: (instanceId: string, attentionId: string) =>
    `/v1/instances/${enc(instanceId)}/activity/${enc(attentionId)}/read`,
  attentionAcknowledge: (instanceId: string, attentionId: string) =>
    `/v1/instances/${enc(instanceId)}/activity/${enc(attentionId)}/acknowledge`,

  // ── Approvals (index only — no generic decision endpoint) ─────────────────
  approvals: '/v1/approvals',

  // ── Receipts ──────────────────────────────────────────────────────────────
  receipts: (instanceId: string) => `/v1/instances/${enc(instanceId)}/receipts`,
  receipt: (instanceId: string, receiptId: string) =>
    `/v1/instances/${enc(instanceId)}/receipts/${enc(receiptId)}`,

  // ── Governed file workspace ──────────────────────────────────────────────
  fileWorkspace: (instanceId: string, operation: string) =>
    `/v1/instances/${enc(instanceId)}/file-workspace/${enc(operation)}`,

  // ── Conversation ──────────────────────────────────────────────────────────
  conversation: (instanceId: string) => `/v1/instances/${enc(instanceId)}/conversation`,
  conversationMessages: (instanceId: string) =>
    `/v1/instances/${enc(instanceId)}/conversation/messages`,
  conversationAssistantWork: (instanceId: string) =>
    `/v1/instances/${enc(instanceId)}/conversation/assistant-work`,
  conversationMessageEvents: (instanceId: string, messageId: string) =>
    `/v1/instances/${enc(instanceId)}/conversation/messages/${enc(messageId)}/events`,
  conversationAttachments: (instanceId: string) =>
    `/v1/instances/${enc(instanceId)}/conversation/attachments`,
  conversationAttachmentDelete: (instanceId: string, attachmentId: string) =>
    `/v1/instances/${enc(instanceId)}/conversation/attachments/${enc(attachmentId)}/delete`,
  conversationExport: (instanceId: string) =>
    `/v1/instances/${enc(instanceId)}/conversation/export`,
  conversationClear: (instanceId: string) =>
    `/v1/instances/${enc(instanceId)}/conversation/clear`,

  // ── Governed execution ────────────────────────────────────────────────────
  actions: (instanceId: string) => `/v1/instances/${enc(instanceId)}/actions`,
  executionEngines: '/v1/execution/engines',
  executionHistory: (instanceId: string) => `/v1/instances/${enc(instanceId)}/execution/history`,
  executionPrepare: (instanceId: string) => `/v1/instances/${enc(instanceId)}/execution/prepare`,
  // ── Governed execution runs ────────────────────────────────────────────────
  executionHost: '/v1/execution-host',
  executionHostWorkloads: '/v1/execution-host/workloads',
  executionHostReceipts: '/v1/execution-host/receipts',
  executionHostWorkloadStatus: (workloadId: string) =>
    `/v1/execution-host/workloads/${enc(workloadId)}`,
  executionHostWorkloadLogs: (workloadId: string) =>
    `/v1/execution-host/workloads/${enc(workloadId)}/logs`,
  executionHostWorkloadStart: '/v1/execution-host/workloads/start',
  executionHostWorkloadStop: '/v1/execution-host/workloads/stop',
  executionHostWorkloadCancel: '/v1/execution-host/workloads/cancel',
  executionHostWorkloadRemove: '/v1/execution-host/workloads/remove',
  executionHostWorkloadExec: '/v1/execution-host/workloads/exec',
  runApprove: (runId: string) => `/v1/runs/${enc(runId)}/approve`,
  runExecute: (runId: string) => `/v1/runs/${enc(runId)}/execute`,
  runCancel: (runId: string) => `/v1/runs/${enc(runId)}/cancel`,
  runProposalApprove: (runId: string) => `/v1/runs/${enc(runId)}/proposal-approve`,
  runProposalReject: (runId: string) => `/v1/runs/${enc(runId)}/proposal-reject`,
  runApply: (runId: string) => `/v1/runs/${enc(runId)}/apply`,
  runBundle: (runId: string) => `/v1/runs/${enc(runId)}/bundle`,
  runStateBench: (runId: string) => `/v1/runs/${enc(runId)}/statebench`,
  templateUpgradeApprove: (instanceId: string) =>
    `/v1/instances/${enc(instanceId)}/template-upgrade/approve`,
  templateUpgradeReject: (instanceId: string) =>
    `/v1/instances/${enc(instanceId)}/template-upgrade/reject`,

  // ── Context lifecycle ─────────────────────────────────────────────────────
  contextLifecycle: (instanceId: string) => `/v1/instances/${enc(instanceId)}/context-lifecycle`,
  contextPreference: (instanceId: string) =>
    `/v1/instances/${enc(instanceId)}/context-lifecycle/preference`,
  contextCompact: (instanceId: string) => `/v1/instances/${enc(instanceId)}/context-lifecycle/compact`,
  contextHandoff: (instanceId: string) => `/v1/instances/${enc(instanceId)}/context-lifecycle/handoff`,

  // ── CTO goal execution ────────────────────────────────────────────────────
  goalExecution: (instanceId: string) => `/v1/instances/${enc(instanceId)}/goal-execution`,
  goalExecutionPrepare: (instanceId: string) => `/v1/instances/${enc(instanceId)}/goal-execution/prepare`,
  goalExecutionApprove: (instanceId: string) => `/v1/instances/${enc(instanceId)}/goal-execution/approve`,
  goalExecutionExecute: (instanceId: string) => `/v1/instances/${enc(instanceId)}/goal-execution/execute`,
  goalExecutionReview: (instanceId: string) => `/v1/instances/${enc(instanceId)}/goal-execution/review`,
  goalExecutionClose: (instanceId: string) => `/v1/instances/${enc(instanceId)}/goal-execution/close`,

  // ── Infrastructure ────────────────────────────────────────────────────────
  infrastructure: (instanceId: string) => `/v1/instances/${enc(instanceId)}/infrastructure`,
  infrastructureGrantPrepare: (instanceId: string) =>
    `/v1/instances/${enc(instanceId)}/infrastructure/grant/prepare`,
  infrastructureGrantApprove: (instanceId: string) =>
    `/v1/instances/${enc(instanceId)}/infrastructure/grant/approve`,
  infrastructurePlan: (instanceId: string) => `/v1/instances/${enc(instanceId)}/infrastructure/plan`,
  infrastructureApprove: (instanceId: string) =>
    `/v1/instances/${enc(instanceId)}/infrastructure/approve`,
  infrastructureRun: (instanceId: string) => `/v1/instances/${enc(instanceId)}/infrastructure/run`,

  // ── Recovery and synthetic validation ─────────────────────────────────────
  backup: (instanceId: string) => `/v1/instances/${enc(instanceId)}/backup`,
  recovery: (instanceId: string) => `/v1/instances/${enc(instanceId)}/recovery`,
  restorePlan: (instanceId: string) => `/v1/instances/${enc(instanceId)}/recovery/restore/plan`,
  restoreApprove: (instanceId: string) => `/v1/instances/${enc(instanceId)}/recovery/restore/approve`,
  restoreApply: (instanceId: string) => `/v1/instances/${enc(instanceId)}/recovery/restore/apply`,
  syntheticRun: (instanceId: string) => `/v1/instances/${enc(instanceId)}/synthetic-run`,

  // ── Terminal ──────────────────────────────────────────────────────────────
  terminalPrepare: (instanceId: string) => `/v1/instances/${enc(instanceId)}/terminal/prepare`,
  /** WebSocket path (same-origin; ticket subprotocol `stateport.terminal.v1`). */
  terminalSocket: '/v1/terminal/socket',

  // ── Platform deployments (governed deployment lifecycle) ───────────────────
  deployments: '/v1/deployments',
  deployment: (deploymentId: string) => `/v1/deployments/${enc(deploymentId)}`,
  deploymentPlan: '/v1/deployments/plan',
  deploymentApply: (deploymentId: string) => `/v1/deployments/${enc(deploymentId)}/apply`,
  deploymentStatus: (deploymentId: string) => `/v1/deployments/${enc(deploymentId)}/status`,
  deploymentLogs: (deploymentId: string) => `/v1/deployments/${enc(deploymentId)}/logs`,
  deploymentRestart: (deploymentId: string) => `/v1/deployments/${enc(deploymentId)}/restart`,
  deploymentRemove: (deploymentId: string) => `/v1/deployments/${enc(deploymentId)}/remove`,
  deploymentPurgePlan: (deploymentId: string) => `/v1/deployments/${enc(deploymentId)}/purge/plan`,

  // ── Standing authority (profiles, grants, pause) ───────────────────────────
  authorityIndex: '/v1/authority/index',
  authorityProfiles: '/v1/authority/profiles',
  authorityGrants: '/v1/authority/grants',
  authorityGrant: (grantId: string) => `/v1/authority/grants/${enc(grantId)}`,
  authorityGrantRevoke: (grantId: string) => `/v1/authority/grants/${enc(grantId)}/revoke`,
  authorityPause: '/v1/authority/pause',

  // ── Installed updater projections (read + digest-bound mutation) ───────────
  updaterStatus: '/v1/updater/status',
  updaterPolicy: '/v1/updater/policy',
  updaterRollback: '/v1/updater/rollback',

  // ── Preview route registry (loopback reverse-proxy bindings) ───────────────
  previewRoutes: '/v1/preview-routes',
  previewRouteRevoke: (routeId: string) => `/v1/preview-routes/${enc(routeId)}/revoke`,
  previewRouteRewrite: (routeId: string) => `/v1/preview-routes/${enc(routeId)}/rewrite`,
} as const

/** Terminal protocol constants (contract §15 — binding). */
export const TERMINAL_TICKET_FORMAT = 'stateport.terminal-socket/v1'
export const TERMINAL_SUBPROTOCOL = 'stateport.terminal.v1'

/** Known projection format versions (fail-closed validation). */
export const FORMAT = {
  activityReceiptsProjection: 'stateport.activity-receipts-projection/v1',
  applicationExperienceResolution: 'stateport.application-experience-resolution/v1',
  conversationPresentation: 'stateport.conversation-presentation/v1',
  contextLifecycleView: 'stateport.context-lifecycle-view/v1',
  contextEffectivePolicy: 'stateport.context-lifecycle-effective/v1',
  contextUsage: 'stateport.context-usage/v1',
  goalExecutionView: 'stateport.goal-execution-view/v1',
  infrastructureLocalLibvirt: 'stateport.infrastructure-local-libvirt/v1',
  applicationInstallReceipt: 'stateport.application-install-receipt/v1',
  transcriptExport: 'stateport.transcript-export/v1',
  transcriptRetentionStatus: 'stateport.transcript-retention-status/v1',
  transcriptLifecycleReceipt: 'stateport.transcript-lifecycle-receipt/v1',
} as const
