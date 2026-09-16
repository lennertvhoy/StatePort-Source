/**
 * HTTP client for the operator-authorized control-plane agent run.
 *
 * The backend owns readiness, the sealed provider directory, workspace
 * authority, execution and persistence. This client only transports the
 * bounded projections and validates every response at the boundary; it must
 * never synthesize a run identity or a terminal result.
 */
import { z } from 'zod'

import { endpoints } from './http/endpoints'
import { HttpTransport } from './http/transport'

/** Terminal and in-flight lifecycle values the control plane reports. */
export const agentRunStatusSchema = z.enum(['running', 'completed', 'failed', 'refused'])

export const agentRefusalSchema = z.object({
  reason: z.string(),
  detail: z.string(),
})

export const agentProviderDirectorySchema = z.object({
  configured: z.boolean(),
  present: z.boolean(),
  files: z.object({
    providerEnv: z.boolean(),
    opencodeJson: z.boolean(),
    model: z.boolean(),
  }),
})

export const agentWorkspaceSchema = z.object({
  status: z.string(),
  workloadId: z.string().nullable(),
})

export const agentStatusSchema = z.object({
  available: z.boolean(),
  refusals: z.array(agentRefusalSchema),
  providerDirectory: agentProviderDirectorySchema,
  workspace: agentWorkspaceSchema,
})

/**
 * One run projection. The API omits absent fields; `outputBytes`,
 * `exitStatus`, `finishedAt` and `refusal` are only populated once the
 * control plane has observed them.
 */
export const agentRunSchema = z.object({
  runId: z.string().min(1),
  status: agentRunStatusSchema,
  objective: z.string(),
  exitStatus: z.union([z.string(), z.number(), z.null()]).optional(),
  outputBytes: z.number().int().nonnegative().nullable().optional(),
  startedAt: z.string().nullable().optional(),
  finishedAt: z.string().nullable().optional(),
  refusal: agentRefusalSchema.nullable().optional(),
})

export const agentRunIndexSchema = z.object({
  runs: z.array(agentRunSchema),
})

export const agentRunStartSchema = z.object({
  runId: z.string().min(1),
  status: z.literal('running'),
  objective: z.string(),
  workspaceId: z.string(),
  startedAt: z.string(),
})

export const agentRunOutputSchema = z.object({
  runId: z.string().min(1),
  output: z.string(),
  truncated: z.boolean(),
  outputBytes: z.number().int().nonnegative(),
})

export type AgentRunStatus = z.infer<typeof agentRunStatusSchema>
export type AgentRefusal = z.infer<typeof agentRefusalSchema>
export type AgentProviderDirectory = z.infer<typeof agentProviderDirectorySchema>
export type AgentWorkspace = z.infer<typeof agentWorkspaceSchema>
export type AgentStatus = z.infer<typeof agentStatusSchema>
export type AgentRun = z.infer<typeof agentRunSchema>
export type AgentRunIndex = z.infer<typeof agentRunIndexSchema>
export type AgentRunStarted = z.infer<typeof agentRunStartSchema>
export type AgentRunOutput = z.infer<typeof agentRunOutputSchema>

const transport = new HttpTransport()

export const agentClient = {
  getStatus: () => transport.request(endpoints.agentStatus, { schema: agentStatusSchema }),
  /** Newest-first, bounded by the service. */
  listRuns: () =>
    transport.request(endpoints.agentRuns, { schema: agentRunIndexSchema }).then((index) => index.runs),
  getRun: (runId: string) =>
    transport.request(endpoints.agentRun(runId), { schema: agentRunSchema }),
  getOutput: (runId: string) =>
    transport.request(endpoints.agentRunOutput(runId), { schema: agentRunOutputSchema }),
  startRun: (objective: string) =>
    transport.request(endpoints.agentRunStart, {
      method: 'POST',
      mutation: true,
      body: { objective },
      schema: agentRunStartSchema,
    }),
}

export type AgentClient = typeof agentClient
