/**
 * HTTP domain clients — governed execution (runs), context lifecycle, CTO
 * orchestration (goal execution), infrastructure, and approvals.
 *
 * Honesty rules enforced here:
 * - Run transition responses must match runId + instanceId and carry an
 *   increasing revision; stale/mismatched responses are rejected
 *   (ClientError 'validation').
 * - There are NO generic approval decision endpoints: decisions route to the
 *   specific run / infrastructure endpoints when the approval references a
 *   runId or an infrastructure plan digest; anything else fails closed with
 *   'unavailable' so the UI shows its honest state.
 * - No streaming endpoints exist for runs/plans/orchestration: transitions
 *   are request/response and the progress iterable reports the honest
 *   sequence (prepared → executed → receipt) without invented log lines.
 */
import { z } from 'zod'

import type {
  ApprovalsClient,
  ContextClient,
  InfrastructureClient,
  OrchestrationClient,
  RunsClient,
} from '../client'
import type {
  Approval,
  ContextLifecycle,
  ContextTransitionBinding,
  ContextTransitionResult,
  InfrastructureOperation,
  InfrastructurePlan,
  OrchestrationSession,
  OrchestrationView,
  PlanProgressEvent,
  Receipt,
  RunOperation,
  RunRecord,
} from '../types'
import { ClientError } from '../types'
import { endpoints } from './endpoints'
import {
  mapActions,
  mapApprovalIndex,
  mapContextLifecycle,
  mapEngines,
  mapGoalExecution,
  mapGoalExecutionReceipt,
  mapGrant,
  mapInfrastructure,
  mapInfrastructurePlan,
  mapReceipt,
  mapRun,
  mapRunBundle,
  mapRunHistory,
  mapStateBench,
} from './mappers'
import { HttpTransport } from './transport'
import { resolveReceipt } from './domainsCore'

const unknownPayload = z.unknown()
const sha256Digest = z.string().regex(/^sha256:[0-9a-f]{64}$/)
const templateUpgradeDecisionResponse = z.object({
  approval: z.object({
    id: z.string().min(1),
    instanceId: z.string().min(1),
    status: z.enum(['approved', 'rejected']),
    reason: z.string(),
    metadata: z.object({
      decision: z.object({
        actor: z.string().min(1),
        status: z.enum(['approved', 'rejected']),
        at: z.string().min(1),
      }).passthrough(),
    }).passthrough(),
  }).passthrough(),
}).passthrough()

const infrastructureRunResponse = z.object({
  formatVersion: z.literal('stateport.infrastructure-run/v1'),
  runId: z.string().min(1),
  instanceId: z.string().min(1),
  operation: z.string().min(1),
  planDigest: sha256Digest,
  state: z.literal('completed'),
  receipt: z
    .object({
      instanceId: z.string().min(1),
      planDigest: sha256Digest,
      target: z.object({ targetId: z.string().min(1) }).passthrough(),
    })
    .passthrough(),
}).passthrough()

const infrastructureApprovalResponse = z.object({
  formatVersion: z.literal('stateport.infrastructure-approval/v1'),
  approvalId: z.string().min(1),
  instanceId: z.string().min(1),
  planDigest: sha256Digest,
}).passthrough()

const contextTransitionResponse = z.object({
  artifact: z.object({
    formatVersion: z.enum([
      'stateport.context-compression/v1',
      'stateport.handoff-artifact/v1',
    ]),
    artifactId: z.string().min(1),
    artifactDigest: sha256Digest,
    instanceId: z.string().min(1),
    policyDigest: sha256Digest,
    sourceContinuityDigest: sha256Digest,
    authorityClassification: z.literal('ephemeral_noncanonical'),
    canonicalStateMutation: z.literal(false),
  }),
  receipt: z.object({
    formatVersion: z.literal('stateport.context-lifecycle-receipt/v1'),
    receiptId: z.string().min(1),
    action: z.enum(['compression', 'handoff']),
    outcome: z.literal('completed'),
    instanceId: z.string().min(1),
    policyDigest: sha256Digest,
    inputProvenanceDigest: sha256Digest,
    artifactDigest: sha256Digest,
    authorityClassification: z.literal('operational_noncanonical'),
    canonicalStateMutation: z.literal(false),
    transcriptRetained: z.literal(false),
    receiptDigest: sha256Digest,
  }),
  canonicalStateUnchanged: z.literal(true),
})

function unavailable(what: string, detail: string): ClientError {
  return new ClientError('unavailable', what, { detail })
}

// ─────────────────────────────────────────────────────────────────────────────
// Governed execution runs
// ─────────────────────────────────────────────────────────────────────────────

const RUN_OPERATION_PATHS: Record<RunOperation, (runId: string) => string> = {
  approve: endpoints.runApprove,
  execute: endpoints.runExecute,
  cancel: endpoints.runCancel,
  'proposal-approve': endpoints.runProposalApprove,
  'proposal-reject': endpoints.runProposalReject,
  apply: endpoints.runApply,
}

export class HttpRunsClient implements RunsClient {
  /** Last revision seen per run — stale-response detection. */
  private revisions = new Map<string, number>()
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async listActions(instanceId: string) {
    const payload = await this.transport.request(endpoints.actions(instanceId), { schema: unknownPayload })
    return mapActions(payload, instanceId)
  }

  async listEngines() {
    const payload = await this.transport.request(endpoints.executionEngines, { schema: unknownPayload })
    return mapEngines(payload)
  }

  async getHistory(instanceId: string) {
    const payload = await this.transport.request(endpoints.executionHistory(instanceId), {
      schema: unknownPayload,
    })
    const runs = mapRunHistory(payload, instanceId)
    for (const run of runs) this.revisions.set(run.id, Math.max(run.revision, this.revisions.get(run.id) ?? 0))
    return runs
  }

  async prepare(
    instanceId: string,
    input: { actionId: string; engineId: string; inputs: Record<string, unknown> },
  ): Promise<RunRecord> {
    const payload = await this.transport.request(endpoints.executionPrepare(instanceId), {
      method: 'POST',
      body: {
        expectedInstanceId: instanceId,
        actionId: input.actionId,
        engineId: input.engineId,
        inputs: input.inputs,
      },
      schema: unknownPayload,
    })
    const run = mapRun(payload, instanceId)
    if (run.instanceId !== instanceId) {
      throw new ClientError('validation', 'Prepare returned a run for a different instance', {
        detail: `expected ${instanceId}, got ${run.instanceId}`,
      })
    }
    this.revisions.set(run.id, run.revision)
    return run
  }

  async transition(
    runId: string,
    operation: RunOperation,
    input: { expectedInstanceId: string; expectedRevision: number },
  ): Promise<RunRecord> {
    const path = RUN_OPERATION_PATHS[operation](runId)
    const payload = await this.transport.request(path, {
      method: 'POST',
      body: { expectedInstanceId: input.expectedInstanceId, expectedRevision: input.expectedRevision },
      schema: unknownPayload,
    })
    const run = mapRun(payload, input.expectedInstanceId)
    // Stale/mismatched responses are rejected (contract §"Governed execution").
    if (run.id !== runId) {
      throw new ClientError('validation', 'Run transition returned a mismatched run identity', {
        detail: `expected ${runId}, got ${run.id}`,
      })
    }
    if (run.instanceId !== input.expectedInstanceId) {
      throw new ClientError('validation', 'Run transition returned a mismatched instance identity', {
        detail: `expected ${input.expectedInstanceId}, got ${run.instanceId}`,
      })
    }
    const lastKnown = Math.max(this.revisions.get(runId) ?? 0, input.expectedRevision)
    if (run.revision <= lastKnown) {
      throw new ClientError('validation', 'Run transition returned a stale revision', {
        detail: `revision ${run.revision} did not increase beyond ${lastKnown}`,
      })
    }
    this.revisions.set(runId, run.revision)
    return run
  }

  async getBundle(runId: string) {
    const payload = await this.transport.request(endpoints.runBundle(runId), { schema: unknownPayload })
    return mapRunBundle(payload, runId)
  }

  async getStateBench(runId: string) {
    const payload = await this.transport.request(endpoints.runStateBench(runId), { schema: unknownPayload })
    return mapStateBench(payload, runId)
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Context lifecycle
// ─────────────────────────────────────────────────────────────────────────────

export class HttpContextClient implements ContextClient {
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async getLifecycle(instanceId: string): Promise<ContextLifecycle> {
    const payload = await this.transport.request(endpoints.contextLifecycle(instanceId), {
      schema: unknownPayload,
    })
    return mapContextLifecycle(payload, instanceId)
  }

  async updatePreference(
    instanceId: string,
    input: { expectedPolicyDigest: string; mode: ContextLifecycle['preference'] },
  ): Promise<ContextLifecycle> {
    const payload = await this.transport.request(endpoints.contextPreference(instanceId), {
      method: 'POST',
      body: {
        expectedInstanceId: instanceId,
        expectedPolicyDigest: input.expectedPolicyDigest,
        mode: input.mode,
      },
      schema: unknownPayload,
    })
    return mapContextLifecycle(payload, instanceId)
  }

  private async transition(
    instanceId: string,
    path: string,
    action: 'compression' | 'handoff',
    binding: ContextTransitionBinding,
  ): Promise<ContextTransitionResult> {
    // Exact continuity identity fields — compact/handoff must never claim
    // canonical application state changed.
    const payload = await this.transport.request(path, {
      method: 'POST',
      body: {
        expectedInstanceId: instanceId,
        expectedBaseSha: binding.expectedBaseSha,
        expectedPolicyDigest: binding.expectedPolicyDigest,
        expectedContinuityDigest: binding.expectedContinuityDigest,
      },
      schema: unknownPayload,
    })
    const parsed = contextTransitionResponse.safeParse(payload)
    if (!parsed.success) {
      throw new ClientError(
        'validation',
        'Context transition response failed authority validation',
        {
          detail: parsed.error.issues
            .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
            .join('\n'),
        },
      )
    }
    const { artifact, receipt } = parsed.data
    const expectedArtifactFormat =
      action === 'compression'
        ? 'stateport.context-compression/v1'
        : 'stateport.handoff-artifact/v1'
    const mismatch =
      receipt.action !== action ||
      artifact.formatVersion !== expectedArtifactFormat ||
      receipt.instanceId !== instanceId ||
      artifact.instanceId !== instanceId ||
      receipt.policyDigest !== binding.expectedPolicyDigest ||
      artifact.policyDigest !== binding.expectedPolicyDigest ||
      receipt.inputProvenanceDigest !== binding.expectedContinuityDigest ||
      artifact.sourceContinuityDigest !== binding.expectedContinuityDigest ||
      receipt.artifactDigest !== artifact.artifactDigest
    if (mismatch) {
      throw new ClientError(
        'validation',
        'Context transition returned mismatched authority identities',
        {
          detail:
            'The action, instance, policy, continuity, artifact, or receipt identity did not match the approved request.',
        },
      )
    }
    // The transition response carries the artifact + receipt, not a refreshed
    // view — re-read the projection so the caller sees current truth.
    const lifecycle = await this.getLifecycle(instanceId)
    return {
      lifecycle,
      receiptId: receipt.receiptId,
      summary:
        'Context transition recorded; canonical application state is unchanged.',
    }
  }

  compact(instanceId: string, input: ContextTransitionBinding): Promise<ContextTransitionResult> {
    return this.transition(
      instanceId,
      endpoints.contextCompact(instanceId),
      'compression',
      input,
    )
  }

  handoff(instanceId: string, input: ContextTransitionBinding): Promise<ContextTransitionResult> {
    return this.transition(
      instanceId,
      endpoints.contextHandoff(instanceId),
      'handoff',
      input,
    )
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// CTO orchestration — mapped onto goal-execution endpoints
// ─────────────────────────────────────────────────────────────────────────────

export class HttpOrchestrationClient implements OrchestrationClient {
  readonly canStop = false
  readonly canRejectReview = false
  /** sessionId → instanceId (from the last projection or transition). */
  private owners = new Map<string, string>()
  /** Stable application identity observed for each active goal execution. */
  private applicationIds = new Map<string, string>()
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  private remember(session: OrchestrationSession | null, instanceId: string): OrchestrationSession | null {
    if (session) this.owners.set(session.id, instanceId)
    return session
  }

  private mapView(payload: unknown, instanceId: string) {
    const view = mapGoalExecution(
      payload,
      instanceId,
      this.applicationIds.get(instanceId),
    )
    if (view.applicationId !== undefined) {
      this.applicationIds.set(instanceId, view.applicationId)
    }
    return view
  }

  private resolveOwner(sessionId: string): string {
    // Session ids are `orch_<instanceId>` in the mapping; the cache covers
    // any future id shape.
    const cached = this.owners.get(sessionId)
    if (cached) return cached
    if (sessionId.startsWith('orch_')) return sessionId.slice('orch_'.length)
    throw unavailable(
      'The owning application of this orchestration session is unknown',
      'Read the current goal execution first.',
    )
  }

  private async readView(instanceId: string) {
    const payload = await this.transport.request(endpoints.goalExecution(instanceId), {
      schema: unknownPayload,
    })
    const view = this.mapView(payload, instanceId)
    this.remember(view.session, instanceId)
    return view
  }

  private requireTransitionIdentity(
    value: string | undefined,
    label: string,
  ): string {
    if (!value) {
      throw new ClientError('validation', `Goal execution carried no ${label}`, {
        detail: `The connected service requires an exact ${label} for the next governed transition.`,
      })
    }
    return value
  }

  async getCurrent(instanceId: string): Promise<OrchestrationSession | null> {
    return (await this.getView(instanceId)).session
  }

  async getView(instanceId: string): Promise<OrchestrationView> {
    const view = await this.readView(instanceId)
    return {
      session: view.session,
      backendId: view.backendId,
      providerExecution: view.providerExecution,
      canonicalStateEffect: view.canonicalStateEffect,
      backendAvailability: view.backendAvailability,
    }
  }

  private async transitionSession(instanceId: string, path: string, body: Record<string, unknown>): Promise<OrchestrationSession> {
    const payload = await this.transport.request(path, { method: 'POST', body, schema: unknownPayload })
    const view = this.mapView(payload, instanceId)
    if (!view.session) {
      throw new ClientError('validation', `Goal execution transition returned the inactive state "${view.goalState}"`)
    }
    return this.remember(view.session, instanceId)!
  }

  async prepareSlice(
    instanceId: string,
    input: { objective: string; mode: OrchestrationSession['mode'] },
  ): Promise<OrchestrationSession> {
    const current = await this.readView(instanceId)
    return this.transitionSession(instanceId, endpoints.goalExecutionPrepare(instanceId), {
      expectedInstanceId: instanceId,
      expectedRevision: current.revision,
      expectedBaseCommit: this.requireTransitionIdentity(current.baseCommit, 'base commit'),
      mode: input.mode,
      intent: input.objective,
    })
  }

  async approve(sessionId: string): Promise<OrchestrationSession> {
    const instanceId = this.resolveOwner(sessionId)
    const current = await this.readView(instanceId)
    return this.transitionSession(instanceId, endpoints.goalExecutionApprove(instanceId), {
      expectedInstanceId: instanceId,
      expectedRevision: current.revision,
      expectedPlanDigest: this.requireTransitionIdentity(current.planDigest, 'plan digest'),
    })
  }

  /**
   * Execute is request/response in the current contract (no run streaming —
   * that is a documented future capability). The iterable reports the honest
   * transition: running → final state → receipt (when the projection carries
   * one); it never invents log lines.
   */
  async *run(sessionId: string): AsyncIterable<PlanProgressEvent> {
    const instanceId = this.resolveOwner(sessionId)
    const planKey = sessionId
    const current = await this.readView(instanceId)
    yield { type: 'state', planId: planKey, state: 'running' }
    const payload = await this.transport.request(endpoints.goalExecutionExecute(instanceId), {
      method: 'POST',
      body: {
        expectedInstanceId: instanceId,
        expectedRevision: current.revision,
        expectedPlanDigest: this.requireTransitionIdentity(current.planDigest, 'plan digest'),
      },
      schema: unknownPayload,
    })
    const view = this.mapView(payload, instanceId)
    if (view.session) this.remember(view.session, instanceId)
    const session = view.session
    if (!session) {
      yield { type: 'error', planId: planKey, message: `Goal execution entered "${view.goalState}" during execution.` }
      return
    }
    yield { type: 'state', planId: planKey, state: session.state }
  }

  async submitReview(sessionId: string, input: { accepted: boolean; notes?: string }): Promise<OrchestrationSession> {
    const instanceId = this.resolveOwner(sessionId)
    if (!input.accepted) {
      throw unavailable(
        'Sending an orchestration result back is not supported by the connected service',
        'The current backend independently validates this provider-free slice and exposes no operator rejection transition.',
      )
    }
    const current = await this.readView(instanceId)
    return this.transitionSession(instanceId, endpoints.goalExecutionReview(instanceId), {
      expectedInstanceId: instanceId,
      expectedRevision: current.revision,
      expectedExecutionResultDigest: this.requireTransitionIdentity(
        current.executionResultDigest,
        'execution-result digest',
      ),
    })
  }

  async close(sessionId: string): Promise<{ session: OrchestrationSession; receipt: Receipt }> {
    const instanceId = this.resolveOwner(sessionId)
    const current = await this.readView(instanceId)
    const payload = await this.transport.request(endpoints.goalExecutionClose(instanceId), {
      method: 'POST',
      body: {
        expectedInstanceId: instanceId,
        expectedRevision: current.revision,
        expectedReviewDigest: this.requireTransitionIdentity(current.reviewDigest, 'review digest'),
      },
      schema: unknownPayload,
    })
    const view = this.mapView(payload, instanceId)
    const session = view.session
    if (!session) {
      throw new ClientError('validation', `Goal execution close returned the unexpected state "${view.goalState}"`)
    }
    // A closed session is terminal — stop tracking it as current.
    this.owners.delete(sessionId)
    const receipt = mapGoalExecutionReceipt(payload, instanceId, view.applicationId)
    if (!receipt) {
      throw new ClientError('validation', 'Goal execution close returned no closure receipt')
    }
    return { session, receipt }
  }

  /**
   * The goal-execution contract has no stop endpoint (states include
   * `stopped`, but no transition produces it from the documented routes).
   * Fail closed rather than inventing one.
   */
  stop(): Promise<OrchestrationSession> {
    return Promise.reject(
      unavailable(
        'Stopping a goal execution is not supported by the connected service',
        'The contract documents no goal-execution stop endpoint; closing is the terminal transition.',
      ),
    )
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Infrastructure
// ─────────────────────────────────────────────────────────────────────────────

export class HttpInfrastructureClient implements InfrastructureClient {
  readonly canRevokeAuthorization = false
  /** planId → plan (digest resolution for approve/run). */
  private plans = new Map<string, InfrastructurePlan>()
  /** instanceId → prepared grant proposal digest. */
  private grantProposals = new Map<string, string>()
  private grantViews = new Map<string, ReturnType<typeof mapGrant>['grant']>()
  private grantActivationResults = new Map<string, { grant: ReturnType<typeof mapGrant>['grant']; receipt: Receipt }>()
  private planExpiries = new Map<string, string>()
  /** Stable target identity observed for each registered infrastructure instance. */
  private targetIds = new Map<string, string>()
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  private rememberTarget(instanceId: string, targetId: string): string {
    const current = this.targetIds.get(instanceId)
    if (current !== undefined && current !== targetId) {
      throw new ClientError(
        'validation',
        'The infrastructure target identity changed during this session',
        { detail: `expected ${current}, got ${targetId}` },
      )
    }
    this.targetIds.set(instanceId, targetId)
    return targetId
  }

  async getTarget(instanceId: string) {
    const payload = await this.transport.request(endpoints.infrastructure(instanceId), {
      schema: unknownPayload,
    })
    const view = mapInfrastructure(payload, instanceId)
    this.rememberTarget(instanceId, view.target.id)
    if (view.plan) this.plans.set(view.plan.id, view.plan)
    return view.target
  }

  async observe(instanceId: string) {
    const plan = await this.preparePlan(instanceId, 'observe')
    for await (const event of this.runPlan(plan.id)) {
      // The backend receipt is durably recorded; this method returns refreshed
      // target truth to preserve the public client contract.
      void event
    }
    return this.getTarget(instanceId)
  }

  async validateConfiguration(instanceId: string): Promise<{ ok: boolean; detail: string; receipt: Receipt }> {
    const plan = await this.preparePlan(instanceId, 'validate')
    let receipt: Receipt | undefined
    for await (const event of this.runPlan(plan.id)) {
      if (event.type === 'done') receipt = event.receipt
    }
    if (!receipt) {
      throw new ClientError('validation', 'The infrastructure validation run returned no receipt')
    }
    return {
      ok: receipt.validation.state === 'validated',
      detail: receipt.summary,
      receipt,
    }
  }

  /**
   * Health check = prepare the read-only health_check plan and run it
   * immediately (read-only plans need no approval), then re-read the truth.
   */
  async healthCheck(instanceId: string) {
    const plan = await this.preparePlan(instanceId, 'health_check')
    const events = this.runPlan(plan.id)
    let receipt: Receipt | undefined
    for await (const event of events) {
      if (event.type === 'done') receipt = event.receipt
    }
    if (!receipt) {
      throw new ClientError('validation', 'The health check run returned no receipt')
    }
    const target = await this.getTarget(instanceId)
    return { target, receipt }
  }

  async preparePlan(instanceId: string, operation: InfrastructureOperation): Promise<InfrastructurePlan> {
    const payload = await this.transport.request(endpoints.infrastructurePlan(instanceId), {
      method: 'POST',
      body: { operation: operation === 'health_check' ? 'health' : operation },
      schema: unknownPayload,
    })
    const targetId = (await this.getTarget(instanceId)).id
    const record = payload as { expiresAt?: unknown }
    const plan = mapInfrastructurePlan(payload, instanceId, targetId)
    if (typeof record.expiresAt === 'string') this.planExpiries.set(plan.id, record.expiresAt)
    // The approval id is owned by the real approval-index projection. Keep
    // the deep link byte-for-byte aligned with that authority; a presentation
    // alias here would navigate to an approval that cannot exist.
    if (plan.state === 'awaiting_approval') {
      plan.approvalId = `infrastructure_plan:${plan.id}`
    }
    this.plans.set(plan.id, plan)
    return plan
  }

  async getPlan(instanceId: string, planId: string): Promise<InfrastructurePlan> {
    const cached = this.plans.get(planId)
    if (cached) {
      if (cached.instanceId !== instanceId) {
        throw new ClientError(
          'validation',
          'The infrastructure plan belongs to a different application instance',
        )
      }
      return cached
    }
    const payload = await this.transport.request(endpoints.infrastructure(instanceId), {
      schema: unknownPayload,
    })
    const view = mapInfrastructure(payload, instanceId)
    this.rememberTarget(instanceId, view.target.id)
    if (view.plan && view.plan.id === planId) {
      this.plans.set(planId, view.plan)
      return view.plan
    }
    throw new ClientError('http', `Infrastructure plan not found: ${planId}`, { status: 404 })
  }

  /**
   * INTEGRATION ASSUMPTION: the contract has no plan index endpoint; the
   * current plan is derived from the infrastructure projection.
   */
  async listPlans(instanceId: string): Promise<InfrastructurePlan[]> {
    const payload = await this.transport.request(endpoints.infrastructure(instanceId), {
      schema: unknownPayload,
    })
    const view = mapInfrastructure(payload, instanceId)
    this.rememberTarget(instanceId, view.target.id)
    if (view.plan) {
      this.plans.set(view.plan.id, view.plan)
      return [view.plan]
    }

    // The current backend has no plan-index endpoint and its infrastructure
    // projection does not repeat a just-prepared plan. Preserve only plans
    // this client observed from the authoritative prepare response, for this
    // exact instance, and only while their backend expiry remains current.
    // This keeps the reviewed plan available across the same-SPA trip to the
    // owning Approvals surface without inventing durable plan history.
    const now = Date.now()
    return [...this.plans.values()]
      .filter((plan) => {
        if (plan.instanceId !== instanceId) return false
        const expiresAt = this.planExpiries.get(plan.id)
        return expiresAt === undefined || new Date(expiresAt).getTime() > now
      })
      // Map insertion order is the client-observation order. Backend
      // timestamps are second-granularity, so two plans prepared in one
      // second cannot be safely ordered by createdAt alone.
      .reverse()
  }

  private resolvePlan(planId: string): InfrastructurePlan {
    const plan = this.plans.get(planId)
    if (!plan) {
      throw unavailable(
        'The infrastructure plan is unknown to this session',
        'Prepare or list plans first so the plan digest can be resolved honestly.',
      )
    }
    return plan
  }

  async *runPlan(planId: string, input?: { approvalId?: string }): AsyncIterable<PlanProgressEvent> {
    const plan = this.resolvePlan(planId)
    const digest = plan.digest.value
    void input
    if (plan.requiresApproval && !plan.coveredByAuthorization && plan.state !== 'approved') {
      throw new ClientError('validation', 'The exact infrastructure plan has not been approved')
    }
    yield { type: 'state', planId, state: 'running' }
    const payload = await this.transport.request(endpoints.infrastructureRun(plan.instanceId), {
      method: 'POST',
      body: { planDigest: digest },
      schema: unknownPayload,
    })
    const parsedRun = infrastructureRunResponse.safeParse(payload)
    if (!parsedRun.success) {
      throw new ClientError(
        'validation',
        'The infrastructure run response did not match the current contract',
        {
          detail: parsedRun.error.issues
            .map((issue) => issue.path.join('.') || 'run')
            .join(', '),
        },
      )
    }
    const run = parsedRun.data
    const backendOperation = plan.operation === 'health_check' ? 'health' : plan.operation
    if (
      run.instanceId !== plan.instanceId ||
      run.operation !== backendOperation ||
      run.planDigest !== digest ||
      run.receipt.instanceId !== plan.instanceId ||
      run.receipt.planDigest !== digest ||
      run.receipt.target.targetId !== plan.targetId
    ) {
      throw new ClientError(
        'validation',
        'The infrastructure run response did not match the exact approved plan',
        {
          detail:
            'The instance, target, operation, plan digest, and receipt identities must all match.',
        },
      )
    }
    const receipt = await resolveReceipt(this.transport, plan.instanceId, payload)
    yield { type: 'done', planId, receipt }
  }

  async getAuthorization(instanceId: string) {
    const payload = await this.transport.request(endpoints.infrastructure(instanceId), {
      schema: unknownPayload,
    })
    const view = mapInfrastructure(payload, instanceId)
    this.rememberTarget(instanceId, view.target.id)
    if (view.grant) {
      this.grantViews.set(instanceId, view.grant.grant)
      if (view.grant.proposalDigest) this.grantProposals.set(instanceId, view.grant.proposalDigest.value)
    }
    return view.grant?.grant ?? null
  }

  /** Daily-driver grant: prepare the proposal (status proposed). */
  async proposeAuthorization(instanceId: string) {
    const payload = await this.transport.request(endpoints.infrastructureGrantPrepare(instanceId), {
      method: 'POST',
      body: {},
      schema: unknownPayload,
    })
    const targetId = (await this.getTarget(instanceId)).id
    const view = mapGrant(payload, instanceId, targetId)
    if (!view.proposalDigest) {
      throw new ClientError('validation', 'The grant proposal carried no proposal digest')
    }
    this.grantProposals.set(instanceId, view.proposalDigest.value)
    this.grantViews.set(instanceId, view.grant)
    return view.grant
  }

  /** Approve the prepared proposal with its exact digest. */
  async activateAuthorization(instanceId: string, input: { approvalId: string }) {
    // The approval identity is held by the UI; the contract approves the
    // grant by its proposal digest.
    void input
    const activated = this.grantActivationResults.get(instanceId)
    if (activated) return activated
    const proposalDigest = this.grantProposals.get(instanceId)
    if (!proposalDigest) {
      throw unavailable(
        'No prepared grant proposal is known for this application',
        'Prepare the grant proposal first; its digest is required for approval.',
      )
    }
    const payload = await this.transport.request(endpoints.infrastructureGrantApprove(instanceId), {
      method: 'POST',
      body: { proposalDigest },
      schema: unknownPayload,
    })
    const targetId = (await this.getTarget(instanceId)).id
    const record = (payload ?? {}) as { grant?: unknown }
    const view = mapGrant(record.grant ?? payload, instanceId, targetId)
    const receipt = await resolveReceipt(this.transport, instanceId, payload)
    const result = { grant: view.grant, receipt }
    this.grantViews.set(instanceId, view.grant)
    this.grantActivationResults.set(instanceId, result)
    return result
  }

  markPlanApproved(
    planDigest: string,
    approval: unknown,
    expectedInstanceId: string,
  ): void {
    const parsedApproval = infrastructureApprovalResponse.safeParse(approval)
    if (!parsedApproval.success) {
      throw new ClientError(
        'validation',
        'The infrastructure approval did not match the current contract',
        {
          detail: parsedApproval.error.issues
            .map((issue) => issue.path.join('.') || 'approval')
            .join(', '),
        },
      )
    }
    const record = parsedApproval.data
    if (record.planDigest !== planDigest) {
      throw new ClientError(
        'validation',
        'The infrastructure approval returned a different plan digest',
      )
    }
    if (record.instanceId !== expectedInstanceId) {
      throw new ClientError(
        'validation',
        'The infrastructure approval belongs to a different application instance',
      )
    }
    for (const [id, plan] of this.plans) {
      if (plan.digest.value !== planDigest) continue
      if (record.instanceId !== plan.instanceId) {
        throw new ClientError(
          'validation',
          'The infrastructure approval belongs to a different application instance',
        )
      }
      this.plans.set(id, {
        ...plan,
        state: 'approved',
        approvalId: record.approvalId,
      })
    }
  }

  markGrantActivated(instanceId: string, payload: unknown): { grant: ReturnType<typeof mapGrant>['grant']; receipt: Receipt } {
    const record = payload as { receipt?: unknown }
    const targetId = this.grantViews.get(instanceId)?.targetId ?? this.targetIds.get(instanceId)
    const grant = mapGrant(payload, instanceId, targetId).grant
    this.rememberTarget(instanceId, grant.targetId)
    const receipt = mapReceipt(record.receipt, instanceId)
    const result = { grant, receipt }
    this.grantViews.set(instanceId, grant)
    this.grantActivationResults.set(instanceId, result)
    return result
  }

  /** The contract has no grant revocation endpoint. */
  revokeAuthorization(): ReturnType<InfrastructureClient['revokeAuthorization']> {
    return Promise.reject(
      unavailable(
        'Revoking an authorization grant is not supported by the connected service',
        'The backend contract documents no grant revoke endpoint.',
      ),
    )
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Approvals — index only; decisions route to the specific endpoints
// ─────────────────────────────────────────────────────────────────────────────

export class HttpApprovalsClient implements ApprovalsClient {
  private cache = new Map<string, Approval>()
  private readonly transport: HttpTransport
  private readonly infrastructure: HttpInfrastructureClient

  constructor(
    transport: HttpTransport,
    runs: RunsClient,
    infrastructure: HttpInfrastructureClient = new HttpInfrastructureClient(transport),
  ) {
    this.transport = transport
    void runs
    this.infrastructure = infrastructure
  }

  async list(filter?: { instanceId?: string; status?: Approval['status']; risk?: Approval['risk']; query?: string }): Promise<Approval[]> {
    const payload = await this.transport.request(endpoints.approvals, { schema: unknownPayload })
    let items = mapApprovalIndex(payload)
    this.cache = new Map(items.map((a) => [a.id, a]))
    if (filter?.instanceId) items = items.filter((a) => a.instanceId === filter.instanceId)
    if (filter?.status) items = items.filter((a) => a.status === filter.status)
    if (filter?.risk) items = items.filter((a) => a.risk === filter.risk)
    if (filter?.query) {
      const q = filter.query.toLowerCase()
      items = items.filter((a) => `${a.title} ${a.operationType} ${a.kind}`.toLowerCase().includes(q))
    }
    return items
  }

  async get(approvalId: string): Promise<Approval> {
    const cached = this.cache.get(approvalId)
    if (cached) return cached
    const items = await this.list()
    const found = items.find((a) => a.id === approvalId)
    if (!found) throw new ClientError('http', `Approval not found: ${approvalId}`, { status: 404 })
    return found
  }

  /**
   * Re-read the approval after a decision; when a decided approval leaves the
   * index, derive the decided state from the known pre-decision entry (the
   * decision already succeeded — no state is invented).
   */
  private async refreshApproval(prior: Approval, decided: Approval['status']): Promise<Approval> {
    const items = await this.list()
    const found = items.find((a) => a.id === prior.id)
    return found ?? { ...prior, status: decided }
  }

  private async refreshTemplateUpgradeApproval(
    prior: Approval,
    decided: 'approved' | 'rejected',
    payload: z.infer<typeof templateUpgradeDecisionResponse>,
  ): Promise<Approval> {
    const authoritative = payload.approval
    const decision = authoritative.metadata.decision
    if (
      !prior.targetId ||
      authoritative.id !== prior.targetId ||
      authoritative.instanceId !== prior.instanceId ||
      authoritative.status !== decided ||
      decision.status !== decided
    ) {
      throw new ClientError('validation', 'The template upgrade decision response changed identity', {
        detail: 'Reload the inbox and review the current approval before acting again.',
      })
    }
    const items = await this.list()
    const found = items.find((item) => item.id === prior.id)
    if (found) {
      if (found.status !== decided) {
        throw new ClientError('validation', 'The template upgrade decision did not converge')
      }
      return found
    }
    return {
      ...prior,
      status: decided,
      decidedAt: decision.at,
      decisionReason: authoritative.reason || undefined,
    }
  }

  /**
   * Decision routing (contract §"Approvals"): there is NO generic decision
   * endpoint. A run approval decides through /v1/runs/:runId/…, an
   * infrastructure plan approval through …/infrastructure/approve, a grant
   * approval through …/infrastructure/grant/approve. Anything else fails
   * closed with 'unavailable'.
   */
  async approve(approvalId: string, input: { expectedDigest: string }): Promise<{ approval: Approval; receipt?: Receipt }> {
    const approval = await this.get(approvalId)
    const decision = this.requireCurrentDecision(approval, input.expectedDigest)
    if ((decision.kind === 'run_approval' || decision.kind === 'run_proposal') && approval.runId) {
      const path =
        decision.kind === 'run_approval'
          ? endpoints.runApprove(approval.runId)
          : endpoints.runProposalApprove(approval.runId)
      await this.transport.request(path, {
        method: 'POST',
        body: {
          expectedInstanceId: decision.expectedInstanceId,
          expectedRevision: decision.expectedRevision,
        },
        schema: unknownPayload,
      })
      return { approval: await this.refreshApproval(approval, 'approved') }
    }
    if (decision.kind === 'infrastructure_plan') {
      const payload = await this.transport.request(endpoints.infrastructureApprove(approval.instanceId), {
        method: 'POST',
        body: { planDigest: decision.expectedDigest },
        schema: unknownPayload,
      })
      this.infrastructure.markPlanApproved(
        decision.expectedDigest,
        payload,
        decision.expectedInstanceId,
      )
      return { approval: await this.refreshApproval(approval, 'approved') }
    }
    if (decision.kind === 'authorization_grant') {
      const payload = await this.transport.request(endpoints.infrastructureGrantApprove(approval.instanceId), {
        method: 'POST',
        body: { proposalDigest: decision.expectedDigest },
        schema: unknownPayload,
      })
      const result = this.infrastructure.markGrantActivated(approval.instanceId, payload)
      return { approval: await this.refreshApproval(approval, 'approved'), receipt: result.receipt }
    }
    if (decision.kind === 'goal_execution') {
      await this.transport.request(endpoints.goalExecutionApprove(approval.instanceId), {
        method: 'POST',
        body: {
          expectedInstanceId: decision.expectedInstanceId,
          expectedRevision: decision.expectedRevision,
          expectedPlanDigest: decision.expectedDigest,
        },
        schema: unknownPayload,
      })
      return { approval: await this.refreshApproval(approval, 'approved') }
    }
    if (decision.kind === 'template_upgrade' && approval.targetId) {
      const payload = await this.transport.request(endpoints.templateUpgradeApprove(approval.instanceId), {
        method: 'POST',
        body: {
          expectedInstanceId: decision.expectedInstanceId,
          approvalId: approval.targetId,
          expectedPlanDigest: decision.expectedDigest,
        },
        schema: templateUpgradeDecisionResponse,
      })
      return {
        approval: await this.refreshTemplateUpgradeApproval(approval, 'approved', payload),
      }
    }
    throw unavailable(
      'This approval cannot be decided through the connected service',
      `Approval decision "${decision.kind}" has no endpoint in the contract; the UI must show its honest state.`,
    )
  }

  async reject(approvalId: string, input: { reason?: string }): Promise<{ approval: Approval; receipt?: Receipt }> {
    const approval = await this.get(approvalId)
    const decision = this.requireCurrentDecision(approval)
    if (decision.kind === 'run_proposal' && approval.runId) {
      if (input.reason !== undefined) {
        throw unavailable(
          'This service cannot record a rejection reason',
          'The authoritative proposal-reject endpoint accepts only the exact instance and revision identities.',
        )
      }
      await this.transport.request(endpoints.runProposalReject(approval.runId), {
        method: 'POST',
        body: {
          expectedInstanceId: decision.expectedInstanceId,
          expectedRevision: decision.expectedRevision,
        },
        schema: unknownPayload,
      })
      return { approval: await this.refreshApproval(approval, 'rejected') }
    }
    if (decision.kind === 'template_upgrade' && approval.targetId) {
      const payload = await this.transport.request(endpoints.templateUpgradeReject(approval.instanceId), {
        method: 'POST',
        body: {
          expectedInstanceId: decision.expectedInstanceId,
          approvalId: approval.targetId,
          expectedPlanDigest: decision.expectedDigest,
          ...(input.reason === undefined ? {} : { reason: input.reason }),
        },
        schema: templateUpgradeDecisionResponse,
      })
      return {
        approval: await this.refreshTemplateUpgradeApproval(approval, 'rejected', payload),
      }
    }
    throw unavailable(
      'Rejecting this approval is not supported by the connected service',
      'The contract only documents rejection for a pending state-change proposal; other kinds fail closed.',
    )
  }

  private requireCurrentDecision(approval: Approval, expectedDigest?: string): Approval['decision'] {
    const decision = approval.decision
    if (
      decision.expectedInstanceId !== approval.instanceId ||
      decision.expectedDigest !== approval.planDigest.value ||
      (expectedDigest !== undefined && expectedDigest !== decision.expectedDigest)
    ) {
      throw new ClientError('validation', 'The approval identity changed before the decision', {
        detail: 'Reload the inbox and review the current instance, revision, and digest.',
      })
    }
    if (
      (decision.kind === 'run_approval' || decision.kind === 'run_proposal' || decision.kind === 'goal_execution') &&
      decision.expectedRevision === undefined
    ) {
      throw new ClientError('validation', 'The approval carries no exact current revision')
    }
    return decision
  }
}
