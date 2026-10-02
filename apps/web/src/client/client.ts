/**
 * StatePortClient — the replaceable typed client boundary.
 *
 * Components and stores never call fetch/localStorage directly; they consume
 * these domain clients. Two implementations exist:
 *   - `MockClient` (development/demo, deterministic, latency-simulated)
 *   - `HttpClient` (production, same-origin StatePort service)
 *
 * Contract rules shared by both adapters:
 * - Reads never mutate; writes return the affected entities (and receipts
 *   where governance produces one).
 * - Domain-expected failures (write conflict, path policy) come back as
 *   result unions; transport/availability failures throw `ClientError`.
 * - Every response is validated against `schemas` at the boundary.
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
  AuthorityGrantDetail,
  AuthorityIndex,
  AuthorityGrantsIndex,
  AuthorityPauseInput,
  AuthorityProfileIndex,
  AuthorityRevokeInput,
  BuildInfo,
  CatalogPackage,
  CanonicalSourceOperatorView,
  CanonicalSourcePublicView,
  CatalogInstallResult,
  CommandResult,
  ContextChip,
  ContextLifecycle,
  ContextPreference,
  ContextTransitionBinding,
  ContextTransitionResult,
  Conversation,
  DevelopmentSourceResolution,
  DevelopmentSourceVerificationInput,
  DeleteFileResult,
  ExecutionEngine,
  CreateFileResult,
  FileEntry,
  FileNode,
  GlobalSettings,
  GovernedAction,
  InfrastructureOperation,
  InfrastructurePlan,
  InfrastructureTarget,
  GlobalSettingsRollbackHistory,
  LocalServiceStatus,
  MessageStream,
  NotificationItem,
  OperationRecord,
  OrchestrationMode,
  OrchestrationSession,
  OrchestrationView,
  PlanProgressEvent,
  PlatformDeploymentDetail,
  PlatformDeploymentIndex,
  PlatformDeploymentMutationResult,
  PlatformDeploymentPlanInput,
  PlatformDeploymentPlanResult,
  PlatformStateBenchView,
  PreviewRouteMutation,
  PreviewRouteIndex,
  PreviewRouteRegisterInput,
  PreviewRouteRewriteInput,
  Receipt,
  ReceiptFilter,
  RecoveryStatus,
  RepositoryCandidate,
  RepositoryInspection,
  RepositoryRegistration,
  RestoreApproval,
  RestorePlan,
  RestoreReceipt,
  RenameFileResult,
  RunBundle,
  RunOperation,
  RunRecord,
  RunTransitionInput,
  SessionInfo,
  StateBenchResult,
  TerminalSession,
  TerminalSessionEvent,
  TerminalTarget,
  UpdaterPolicyInput,
  UpdaterPolicyProjection,
  UpdaterRollbackPlanResult,
  UpdaterRollbackProjection,
  UpdaterStatus,
  WriteFileResult,
} from './types'

export interface SessionClient {
  getSession(): Promise<SessionInfo>
  getLocalServiceStatus(): Promise<LocalServiceStatus>
  getBuildInfo(): Promise<BuildInfo>
  /** Ask the service chip's Retry action to re-establish contact. */
  reconnect(): Promise<LocalServiceStatus>
}

export interface ApplicationsClient {
  /** Whether the connected adapter has a durable instance-rename contract. */
  readonly canRename: boolean
  list(): Promise<ApplicationInstance[]>
  get(instanceId: string): Promise<ApplicationInstance>
  rename(instanceId: string, name: string, expectedName?: string): Promise<ApplicationInstance>
  setPinned(instanceId: string, pinned: boolean): Promise<ApplicationInstance>
  /** Records "last opened" for the resume dashboard. */
  touchOpened(instanceId: string): Promise<void>
}

export interface CatalogClient {
  list(): Promise<CatalogPackage[]>
  get(packageId: string): Promise<CatalogPackage>
  /** Install review has already happened in the UI; this creates the instance. */
  createInstance(packageId: string, input: { name: string }): Promise<CatalogInstallResult>
  /** Ask the service to re-scan the reviewed catalog (POST /v1/catalog/refresh). */
  refresh(): Promise<void>
}

/**
 * Canonical application-source projections.
 *
 * The list is safe for every authenticated local user. Exact authority,
 * immutable identities, candidate evidence, and development verification are
 * independently permission-gated by the service for platform operators.
 */
export interface SourcesClient {
  list(): Promise<CanonicalSourcePublicView[]>
  getOperatorDetail(sourceId: string): Promise<CanonicalSourceOperatorView>
  verifyDevelopmentCandidate(input: DevelopmentSourceVerificationInput): Promise<DevelopmentSourceResolution>
}

export interface PlatformStateBenchClient {
  /**
   * Read the path-free verified RunBundle matrix.
   *
   * The caller supplies the status projection it already inspected. The
   * adapter refuses locally before issuing a request unless that projection
   * carries every operator permission bit; the service rechecks authority.
   */
  getMatrix(status: LocalServiceStatus): Promise<PlatformStateBenchView>
}

/** Optimistic-concurrency rollback input (POST …/settings/rollback). */
export interface SettingsRollbackInput {
  expectedRevision: number
  receiptId: string
}

export interface GlobalSettingsClient {
  get(): Promise<GlobalSettings>
  /**
   * Inspect the exact current revision and the backend's bounded, durable
   * rollback targets. This is derived from GET /v1/settings; it does not
   * introduce a second history endpoint or browser authority.
   */
  getRollbackHistory(): Promise<GlobalSettingsRollbackHistory>
  /** Deep partial patch; returns the new effective settings. */
  update(patch: DeepPartial<GlobalSettings>): Promise<GlobalSettings>
  /**
   * Roll back to the state captured before the referenced settings receipt.
   * HTTP: POST /v1/settings/rollback with optimistic concurrency.
   */
  rollback(input: SettingsRollbackInput): Promise<GlobalSettings>
  reset(): Promise<GlobalSettings>
  exportJson(): Promise<string>
  /** Validated with the global-settings schema; invalid input throws ClientError(kind: 'validation'). */
  importJson(json: string): Promise<GlobalSettings>
}

export interface AppSettingsClient {
  get(instanceId: string): Promise<AppSettings>
  update(instanceId: string, patch: DeepPartial<AppSettings>): Promise<AppSettings>
  /** Roll back to the state captured before the referenced settings receipt. */
  rollback(instanceId: string, input: SettingsRollbackInput): Promise<AppSettings>
  reset(instanceId: string): Promise<AppSettings>
}

export interface ActivityClient {
  listActivity(filter?: ActivityFilter): Promise<ActivityItem[]>
  /**
   * `context.instanceId` lets the HTTP adapter address the per-instance
   * endpoint without a lookup; when omitted it resolves from the last
   * fetched projection (fail-closed when unknown).
   */
  markActivityRead(activityId: string, context?: { instanceId?: string }): Promise<void>
  listAttention(instanceId?: string): Promise<AttentionItem[]>
  acknowledgeAttention(attentionId: string, context?: { instanceId?: string }): Promise<AttentionItem>
  listNotifications(): Promise<NotificationItem[]>
  markNotificationRead(notificationId: string, context?: { instanceId?: string }): Promise<void>
  snoozeNotification(notificationId: string, until: string): Promise<void>
}

export interface ApprovalsClient {
  list(filter?: ApprovalFilter): Promise<Approval[]>
  get(approvalId: string): Promise<Approval>
  /**
   * `expectedDigest` must match the approval's current digest — a mismatch
   * means the plan went stale and the approval is rejected as stale.
   */
  approve(approvalId: string, input: { expectedDigest: string }): Promise<{ approval: Approval; receipt?: Receipt }>
  reject(approvalId: string, input: { reason?: string }): Promise<{ approval: Approval; receipt?: Receipt }>
}

/**
 * Send input. `clientMessageId` is the idempotent client-generated identity
 * required by the backend contract — retries MUST preserve it. The mock
 * generates one when omitted; the HTTP adapter preserves any provided value.
 *
 * `resumeMessageId` re-attaches to an in-flight assistant stream (e.g. after
 * a reload found a persisted `state: 'streaming'` message) instead of
 * recording a new user message. Adapters without a live stream for that
 * message reject with a ClientError so the surface can mark the message
 * interrupted and offer retry.
 */
export interface ConversationSendInput {
  content: string
  attachments?: Attachment[]
  contextChips?: ContextChip[]
  clientMessageId?: string
  resumeMessageId?: string
}

export interface ConversationClient {
  get(instanceId: string): Promise<Conversation>
  /**
   * Records the user's message and returns it plus the stream for the
   * assistant reply. Consume the stream to completion or call `stop()`.
   */
  sendMessage(
    instanceId: string,
    input: ConversationSendInput,
  ): Promise<{ userMessage: Conversation['messages'][number]; stream: MessageStream }>
  /**
   * The mock streaming contract in its canonical shape: send a message and
   * get back an async iterable (with `stop()`) of stream chunks.
   * Equivalent to `sendMessage(...)` then consuming `.stream`.
   *
   * With `input.resumeMessageId` no new message is recorded: the returned
   * stream continues the in-flight assistant message, and `userMessage` is
   * the user message it answers (`null` when there is none).
   */
  streamMessage(
    instanceId: string,
    input: ConversationSendInput,
  ): Promise<{ userMessage: Conversation['messages'][number] | null; stream: MessageStream }>
  /** Retry the last failed/stopped assistant response. */
  retryLast(instanceId: string): Promise<MessageStream>
  uploadAttachment(
    instanceId: string,
    input: { name: string; mimeType: string; sizeBytes: number; contentBase64?: string },
  ): Promise<Attachment>
  deleteAttachment(instanceId: string, attachmentId: string): Promise<void>
  exportConversation(instanceId: string): Promise<{ markdown: string; receipt: Receipt }>
  clearConversation(instanceId: string): Promise<{ receipt: Receipt }>
}

export interface ReceiptsClient {
  list(filter?: ReceiptFilter): Promise<Receipt[]>
  /**
   * Resolve a receipt, optionally binding it to the application-scoped route
   * that requested the detail. A conflicting explicit identity fails closed.
   */
  get(receiptId: string, expectedInstanceId?: string): Promise<Receipt>
  /** Integrity check for the detail drawer. */
  verify(receiptId: string): Promise<{ ok: boolean; detail: string }>
  exportJson(instanceId: string): Promise<string>
}

export interface FilesClient {
  listTree(instanceId: string): Promise<FileNode[]>
  read(instanceId: string, path: string): Promise<FileEntry>
  /**
   * Governed write: requires the revision the editor based its changes on.
   * Produces a FileChange + Receipt on success; conflict and path-policy
   * rejections come back as `{ ok: false, … }`.
   */
  write(
    instanceId: string,
    path: string,
    input: { content: string; expectedRevision: string },
  ): Promise<WriteFileResult>
  /**
   * Governed regular-file creation. A prior tree listing supplies the exact
   * Git base; the broker still prepares and previews an exact diff before the
   * adapter confirms it.
   */
  create(
    instanceId: string,
    path: string,
    input: { content: string },
  ): Promise<CreateFileResult>
  /**
   * Governed regular-file rename. `expectedRevision` must come from an exact
   * read of `sourcePath`; directory moves are intentionally unsupported.
   */
  rename(
    instanceId: string,
    sourcePath: string,
    input: { destinationPath: string; expectedRevision: string },
  ): Promise<RenameFileResult>
  /**
   * Governed regular-file deletion. `expectedRevision` must come from an exact
   * read and the destructive product confirmation remains a separate gate.
   */
  delete(
    instanceId: string,
    path: string,
    input: { expectedRevision: string },
  ): Promise<DeleteFileResult>
}

/**
 * The application-scoped file workbench boundary. Production uses the
 * governed broker's read → prepare → preview → exact-confirm → commit
 * transaction; capability gating hides the tool unless the effective
 * experience descriptor declares file_viewer/editor.
 */
export type FileWorkbenchAdapter = FilesClient

export interface TerminalClient {
  /** Mock line-command interpreter or authenticated production raw PTY. */
  readonly inputMode: 'line_commands' | 'raw_pty'
  listTargets(instanceId: string, scope?: 'workspace'): Promise<TerminalTarget[]>
  listSessions(instanceId: string): Promise<TerminalSession[]>
  createSession(instanceId: string, targetId: string, name?: string): Promise<TerminalSession>
  renameSession(sessionId: string, name: string): Promise<TerminalSession>
  /**
   * Explicit connect (opening the view never connects). `dimensions` feeds
   * the HTTP terminal/prepare request; the mock ignores it.
   */
  connect(sessionId: string, dimensions?: { columns?: number; rows?: number }): Promise<TerminalSession>
  disconnect(sessionId: string): Promise<TerminalSession>
  reconnect(sessionId: string): Promise<TerminalSession>
  endSession(sessionId: string): Promise<TerminalSession>
  /** Runs one command line in the mock PTY; output also flows to subscribers. */
  runCommand(sessionId: string, command: string): Promise<CommandResult>
  /**
   * Raw input channel for real PTY transports (HTTP WebSocket). The mock
   * accepts it too, feeding bytes through its line discipline, so raw-mode
   * views keep working in both adapters. Throws when the session is not
   * connected.
   */
  sendInput(sessionId: string, data: string): void
  /**
   * Report a viewport resize to the PTY. No-op in the mock; the HTTP
   * transport forwards it when the protocol supports it.
   */
  resize(sessionId: string, columns: number, rows: number): void
  /** Output/state events for a session; returns an unsubscribe function. */
  subscribe(sessionId: string, listener: (event: TerminalSessionEvent) => void): () => void
}

export interface InfrastructureClient {
  /** Whether this adapter exposes a durable, receipted grant-revocation transition. */
  readonly canRevokeAuthorization: boolean
  /** Current truth: target, VM, SSH, health, repository. */
  getTarget(instanceId: string): Promise<InfrastructureTarget>
  /** Read-only observation; refreshes VM/SSH/health truth, records activity. */
  observe(instanceId: string): Promise<InfrastructureTarget>
  validateConfiguration(instanceId: string): Promise<{ ok: boolean; detail: string; receipt: Receipt }>
  healthCheck(instanceId: string): Promise<{ target: InfrastructureTarget; receipt: Receipt }>
  /** Prepare (never run) a plan for an operation. */
  preparePlan(instanceId: string, operation: InfrastructureOperation): Promise<InfrastructurePlan>
  getPlan(instanceId: string, planId: string): Promise<InfrastructurePlan>
  listPlans(instanceId: string): Promise<InfrastructurePlan[]>
  /**
   * Run a prepared/approved plan. Read-only plans run immediately;
   * routine plans run when covered by an active authorization, otherwise
   * they require `approvalId` of an approved approval. Returns a progress
   * stream; the final event carries the receipt.
   */
  runPlan(planId: string, input?: { approvalId?: string }): AsyncIterable<PlanProgressEvent>
  getAuthorization(instanceId: string): Promise<AuthorizationGrant | null>
  /** Propose (status: proposed) a daily-driver authorization for the target. */
  proposeAuthorization(instanceId: string): Promise<AuthorizationGrant>
  /** Activate a proposed authorization after its approval was granted. */
  activateAuthorization(instanceId: string, input: { approvalId: string }): Promise<{ grant: AuthorizationGrant; receipt: Receipt }>
  revokeAuthorization(instanceId: string): Promise<{ grant: AuthorizationGrant; receipt: Receipt }>
}

export interface OrchestrationClient {
  /** Whether an in-flight slice can be stopped through the connected service. */
  readonly canStop: boolean
  /** Whether a prepared or approved slice can be discarded before execution. */
  readonly canDiscard: boolean
  /** Whether independent review can reject/send back a result. */
  readonly canRejectReview: boolean
  getCurrent(instanceId: string): Promise<OrchestrationSession | null>
  /**
   * The full current view: session plus the typed backend availability, so
   * the UI can show an honest unavailable state instead of offering active
   * orchestration that the connected backend would always refuse.
   */
  getView(instanceId: string): Promise<OrchestrationView>
  /** Enter objective + mode, prepare the bounded slice (stages 1–3). */
  prepareSlice(
    instanceId: string,
    input: { objective: string; mode: OrchestrationMode },
  ): Promise<OrchestrationSession>
  /** Approve after reviewing base/plan/permissions/budget (stage 8). */
  approve(sessionId: string, expectedRevision?: number): Promise<OrchestrationSession>
  /** Discard an unstarted slice and release its approval; creates no success receipt. */
  discard(sessionId: string, expectedRevision?: number): Promise<void>
  /** Run inspection/execution (stage 9) with progress events. */
  run(sessionId: string, expectedRevision?: number): AsyncIterable<PlanProgressEvent>
  /** Record review + independent review (stages 10–11). */
  submitReview(sessionId: string, input: { accepted: boolean; notes?: string }, expectedRevision?: number): Promise<OrchestrationSession>
  /** Close and stop; creates the receipt (stages 12–13). */
  close(sessionId: string, expectedRevision?: number): Promise<{ session: OrchestrationSession; receipt: Receipt }>
  /** Emergency stop: halts a running session honestly (state: cancelled). */
  stop(sessionId: string): Promise<OrchestrationSession>
}

export interface RecoveryClient {
  getBackupState(instanceId: string): Promise<ApplicationInstance['recovery']>
  runBackup(instanceId: string): Promise<{ recovery: ApplicationInstance['recovery']; receipt: Receipt }>
  getStatus(instanceId: string): Promise<RecoveryStatus>
  planRestore(
    instanceId: string,
    input: { backupReceiptId: string; destinationInstanceId: string; destinationName: string | null },
  ): Promise<RestorePlan>
  approveRestore(instanceId: string, planDigest: string): Promise<RestoreApproval>
  applyRestore(
    instanceId: string,
    input: { planDigest: string; approvalDigest: string },
  ): Promise<RestoreReceipt>
}

export interface OperationsClient {
  list(): Promise<OperationRecord[]>
  get(operationId: string): Promise<OperationRecord>
  pause(operationId: string): Promise<OperationRecord>
  cancel(operationId: string): Promise<OperationRecord>
}

/**
 * Governed execution runs (contract §"Governed execution"). New domain client —
 * additive to the boundary; backed by /v1/instances/:id/execution/* and
 * /v1/runs/:runId/* in the HTTP adapter.
 */
export interface RunsClient {
  listActions(instanceId: string): Promise<GovernedAction[]>
  listEngines(): Promise<ExecutionEngine[]>
  getHistory(instanceId: string): Promise<RunRecord[]>
  prepare(
    instanceId: string,
    input: { actionId: string; engineId: string; inputs: Record<string, unknown> },
  ): Promise<RunRecord>
  /**
   * Transition a run. Responses must match the run ID, the instance ID, and
   * carry an increasing revision — stale/mismatched responses are rejected
   * with ClientError(kind: 'validation').
   */
  transition(runId: string, operation: RunOperation, input: RunTransitionInput): Promise<RunRecord>
  getBundle(runId: string): Promise<RunBundle>
  getStateBench(runId: string): Promise<StateBenchResult>
}

/** Context lifecycle (contract §"Context lifecycle"). New additive domain client. */
export interface ContextClient {
  getLifecycle(instanceId: string): Promise<ContextLifecycle>
  updatePreference(
    instanceId: string,
    input: { expectedPolicyDigest: string; mode: ContextPreference },
  ): Promise<ContextLifecycle>
  compact(instanceId: string, input: ContextTransitionBinding): Promise<ContextTransitionResult>
  handoff(instanceId: string, input: ContextTransitionBinding): Promise<ContextTransitionResult>
}

/**
 * Sanctioned execution-host control-plane proxy (the ONLY browser path to the
 * confined daemon). Read operations are session-gated; state-changing
 * operations additionally require the CSRF mutation gate on the backend.
 * Every result is a bounded daemon receipt — never fabricated state.
 */
export interface WorkspaceAuthorityProjection {
  instanceId: string
  applicationId: string
  displayName: string
  catalogIdentityDigest: string
  status: 'available' | 'issued' | 'unavailable'
  refusal?: { reason: string; detail: string }
  issuer?: WorkspaceAuthorityIssuer
  issued?: Record<string, unknown>
}

export interface WorkspaceAuthoritySource {
  baseRevision: string
  commitObject: string
  sourceInventory: Array<{ path: string; mode: '100644' | '100755'; contentDigest: string }>
  sourceArchive: {
    formatVersion: 'stateport.deployment-context-archive/v1'
    archiveDigest: string
    archiveBytes: number
    contextDigest: string
    fileCount: number
  }
  descriptorDigest: string
}

export interface WorkspaceAuthorityIssuerBase {
    issuerContextDigest: string
    profileId: string
    profileDigest: string
    sourceMode: 'empty' | 'reviewed-commit'
    operations?: string[]
    grantExpiresAtLimit: string
    profile: {
      image: { reference: string }
      parameters: { cpuQuotaPercent: number; diskMaxBytes: number; networkMode: string; shell?: string[] }
      resources: { memoryMaxBytes: number; pidsMax: number }
      timeoutSeconds: number
      outputByteBound: number
    }
  }

export interface WorkspaceAuthorityEmptyIssuer extends WorkspaceAuthorityIssuerBase {
  profileId: 'stateport.empty-workspace/v1' | 'stateport.empty-workspace-terminal/v1'
  sourceMode: 'empty'
}

export interface WorkspaceAuthorityReviewedIssuer extends WorkspaceAuthorityIssuerBase {
  profileId: 'stateport.reviewed-source-workspace-terminal/v1'
  sourceMode: 'reviewed-commit'
}

export type WorkspaceAuthorityIssuer = WorkspaceAuthorityEmptyIssuer | WorkspaceAuthorityReviewedIssuer

export interface WorkspaceAuthorityRequestBase {
  instanceId: string
  applicationId: string
  catalogIdentityDigest: string
  issuerContextDigest: string
  profileDigest: string
  createdAt: string
  expiresAt: string
  grantExpiresAt: string
  requestDigest: string
}

export interface WorkspaceAuthorityRequestV1 extends WorkspaceAuthorityRequestBase {
  formatVersion: 'stateport.workspace-authority-request/v1'
  sourceMode: 'empty'
}

export interface WorkspaceAuthorityRequestV2 extends WorkspaceAuthorityRequestBase {
  formatVersion: 'stateport.workspace-authority-request/v2'
  sourceMode: 'reviewed-commit'
  source: WorkspaceAuthoritySource
  sourceDigest: string
}

export type WorkspaceAuthorityRequest = WorkspaceAuthorityRequestV1 | WorkspaceAuthorityRequestV2

export interface WorkspaceAuthorityPreparation {
  request: WorkspaceAuthorityRequest
  review: WorkspaceAuthorityProjection
}

export interface ExecutionHostClient {
  workspaceAuthority(instanceId: string): Promise<WorkspaceAuthorityProjection>
  prepareWorkspaceAuthority(instanceId: string, request: WorkspaceAuthorityRequestInput): Promise<WorkspaceAuthorityPreparation>
  status(): Promise<ExecutionHostStatus>
  listWorkloads(): Promise<ExecutionHostResult>
  listReceipts(): Promise<ExecutionHostReceiptIndex>
  workloadStatus(workloadId: string): Promise<ExecutionHostResult>
  workloadLogs(workloadId: string): Promise<ExecutionHostResult>
  createDefaultWorkload(instanceId?: string, sourceReviewDigest?: string): Promise<ExecutionHostResult>
  startWorkload(workloadId: string): Promise<ExecutionHostResult>
  stopWorkload(workloadId: string): Promise<ExecutionHostResult>
  cancelWorkload(workloadId: string): Promise<ExecutionHostResult>
  removeWorkload(workloadId: string): Promise<ExecutionHostResult>
  execWorkload(workloadId: string, argv: string[]): Promise<ExecutionHostResult>
}

export type WorkspaceAuthorityRequestInput =
  | { profileDigest: string; sourceMode: 'empty'; grantExpiresAt: string }
  | { profileDigest: string; sourceMode: 'reviewed-commit'; grantExpiresAt: string }

export interface ExecutionHostStatus {
  status: 'available' | 'unavailable'
  reason?: string
  detail?: string
  contractVersion?: number
  engine?: string | null
  engineVersion?: string | null
  peerIdentity?: {
    mechanism: string
  }
  workloadKinds?: string[]
  grantId?: string
  grantBound: boolean
}

export interface ExecutionHostOperationReceipt {
  receiptId: string
  receiptType: 'stateport.execution-host-operation-receipt/v1'
  action: string
  status: 'accepted' | 'refused'
  createdAt: string
  sourceKind: 'execution_host'
  actorId?: string
  operationId: string
  requestDigest: string
  resultDigest: string
  workloadId?: string | null
  outputDigest?: string
  outputBytes?: number
}

export interface ExecutionHostReceiptIndex {
  receipts: Array<{
    receiptId: string
    receiptType: string
    action: string
    status: string
    createdAt: string
    sourceKind: string
    payloadDigest: string
  }>
}

export interface ExecutionHostResult {
  operationId?: string
  accepted: boolean
  result?: Record<string, unknown> | unknown[] | null
  observed?: {
    engine?: string | null
    engineVersion?: string | null
    imageDigest?: string | null
    exitStatus?: string | number | null
    startedAt?: string | null
    finishedAt?: string | null
  }
  refusal?: { reason?: string; detail?: string }
  receipt?: ExecutionHostOperationReceipt
}

/**
 * Local repository registration (contract §"Local repository registration").
 * Inspection is read-only; registration requires the inspection digest and an
 * explicit approval flag. Exposed for future wiring.
 */
export interface RepositoryImportClient {
  listLocalCandidates(): Promise<RepositoryCandidate[]>
  inspect(candidateId: string): Promise<RepositoryInspection>
  inspectPublic(url: string, revision: string): Promise<RepositoryInspection>
  register(input: { candidateId: string; name: string; inspectionDigest: string; approved: boolean }): Promise<RepositoryRegistration>
  installTemplate(input: {
    candidateId: string
    name: string
    inspection: RepositoryInspection
    approved: boolean
  }): Promise<RepositoryRegistration>
}

/**
 * Platform deployments (contract §"Platform deployments"). The governed
 * deployment lifecycle the admin CLI drives, projected over HTTP. Every
 * mutation crosses the canonical authority boundary; apply/restart/remove are
 * digest-bound to the exact accepted plan or pending authority run.
 */
export interface PlatformDeploymentsClient {
  list(): Promise<PlatformDeploymentIndex>
  get(deploymentId: string): Promise<PlatformDeploymentDetail>
  plan(input: PlatformDeploymentPlanInput): Promise<PlatformDeploymentPlanResult>
  apply(
    deploymentId: string,
    input: { acceptPlanDigest: string; grantId: string; sliceId?: string },
  ): Promise<PlatformDeploymentMutationResult>
  status(deploymentId: string, input: { grantId: string; sliceId?: string }): Promise<PlatformDeploymentMutationResult>
  logs(
    deploymentId: string,
    input: { grantId: string; sliceId?: string; serviceId?: string; tail?: number },
  ): Promise<PlatformDeploymentMutationResult>
  restart(
    deploymentId: string,
    input: { grantId: string; proposalDigest: string; sliceId?: string },
  ): Promise<PlatformDeploymentMutationResult>
  remove(
    deploymentId: string,
    input: { grantId: string; proposalDigest: string; sliceId?: string },
  ): Promise<PlatformDeploymentMutationResult>
  planPurge(deploymentId: string, input: { grantId: string; sliceId?: string }): Promise<PlatformDeploymentPlanResult>
}

/**
 * Standing authority (contract §"Standing authority"). Profiles and grants
 * are read-only projections of the local authority store. Grant revocation
 * requires an owner directive + reason and is digest-bound to the grant.
 * Pause and unpause require approval bound to the reviewed control digest.
 */
export interface AuthorityClient {
  getIndex(): Promise<AuthorityIndex>
  listProfiles(): Promise<AuthorityProfileIndex>
  listGrants(): Promise<AuthorityGrantsIndex>
  getGrant(grantId: string): Promise<AuthorityGrantDetail>
  revokeGrant(grantId: string, input: AuthorityRevokeInput): Promise<{
    revocation: unknown
    revokedGrantDigest: string
    receiptId: string
    receiptDigest: string
  }>
  setPaused(input: AuthorityPauseInput): Promise<{
    control: unknown
    receiptId: string
    receiptDigest: string
  }>
}

/**
 * Installed updater (contract §"Installed updater"). Status, policy, and
 * rollback are read-only observations of the installed updater state; policy
 * mutation executes through canonical installed authority and is digest-bound
 * to the observed status digest. Rollback *apply* is never exposed over HTTP —
 * it remains an installed-authority CLI operation (`applyBoundary`).
 */
export interface UpdaterClient {
  getStatus(): Promise<UpdaterStatus>
  getPolicy(): Promise<UpdaterPolicyProjection>
  getRollback(): Promise<UpdaterRollbackProjection>
  setPolicy(input: UpdaterPolicyInput): Promise<UpdaterStatus>
  planRollback(input: { expectedStatusDigest: string }): Promise<UpdaterRollbackPlanResult>
}

/**
 * Preview routes (contract §"Preview routes"). The loopback-only reverse-proxy
 * registry. Register/revoke/rewrite are receipted; one active route per
 * capsule/service; rewrite is the atomic rollback path.
 */
export interface PreviewRoutesClient {
  list(): Promise<PreviewRouteIndex>
  register(input: PreviewRouteRegisterInput): Promise<PreviewRouteMutation>
  revoke(routeId: string, input: { reason: string; expectedRouteDigest: string }): Promise<PreviewRouteMutation>
  rewrite(routeId: string, input: PreviewRouteRewriteInput): Promise<PreviewRouteMutation>
}

export type { ScenarioId } from './mock/scenarios'

/** Dev-only Scenario Lab control. Present on both adapters; HTTP throws not_implemented. */
export interface ScenarioClient {
  list(): Promise<{ id: import('./mock/scenarios').ScenarioId; label: string; group: string }[]>
  getActive(): Promise<import('./mock/scenarios').ScenarioId | null>
  setActive(id: import('./mock/scenarios').ScenarioId | null): Promise<void>
  /** Wipe persisted mock state and re-seed. HTTP adapter: not_implemented. */
  resetMockState(): Promise<void>
}

export interface StatePortClient {
  readonly adapter: 'mock' | 'http'
  session: SessionClient
  applications: ApplicationsClient
  catalog: CatalogClient
  sources: SourcesClient
  platformStateBench: PlatformStateBenchClient
  globalSettings: GlobalSettingsClient
  appSettings: AppSettingsClient
  activity: ActivityClient
  approvals: ApprovalsClient
  conversation: ConversationClient
  receipts: ReceiptsClient
  files: FilesClient
  terminal: TerminalClient
  infrastructure: InfrastructureClient
  orchestration: OrchestrationClient
  recovery: RecoveryClient
  operations: OperationsClient
  scenario: ScenarioClient
  /** Governed execution runs (additive domain). */
  runs: RunsClient
  /** Sanctioned execution-host control-plane proxy. */
  executionHost: ExecutionHostClient
  /** Context lifecycle (additive domain). */
  context: ContextClient
  /** Local repository import (additive domain, for future wiring). */
  repositoryImport: RepositoryImportClient
  /** Platform deployment lifecycle (operator surface). */
  platformDeployments: PlatformDeploymentsClient
  /** Standing authority profiles, grants, and pause (operator surface). */
  authority: AuthorityClient
  /** Installed updater status, policy, and rollback (operator surface). */
  updater: UpdaterClient
  /** Preview route registry (loopback reverse-proxy bindings). */
  previewRoutes: PreviewRoutesClient
}

/** Deep partial used by settings update methods. */
export type DeepPartial<T> = T extends object ? { [K in keyof T]?: DeepPartial<T[K]> } : T
