import { z } from 'zod'
import { HttpTransport } from './http/transport'

export const providerStatusSchema = z.object({
  configured: z.boolean(), executableInstalled: z.boolean(), connected: z.boolean(),
  model: z.string().nullable(),
  providerId: z.enum(['codex', 'opencode']).optional(),
  executableStatus: z.enum(['unverified', 'installed', 'missing']).optional(),
  executionRefusal: z.string().nullable().optional(),
  authenticationStatus: z.enum(['unverified', 'authenticated', 'unauthenticated', 'unavailable']),
  requestStatus: z.enum(['unverified', 'succeeded', 'failed']),
  telemetryStatus: z.literal('unavailable'), detail: z.string(),
})
export type ProviderStatus = z.infer<typeof providerStatusSchema>
export const loginFlowSchema = z.object({
  active: z.boolean(),
  phase: z.enum(['pending', 'code', 'authenticated', 'failed', 'expired', 'cancelled']),
  verificationUrl: z.string().nullable(),
  userCode: z.string().nullable(),
  detail: z.string(),
})
export type LoginFlow = z.infer<typeof loginFlowSchema>
const transport = new HttpTransport()
const mutate = (action: string, body: object = {}) => transport.request(`/v1/provider/${action}`, {
  method: 'POST', mutation: true, body, schema: providerStatusSchema,
})
const mutateLoginFlow = (path: string) => transport.request(`/v1/provider/${path}`, {
  method: 'POST', mutation: true, body: {}, schema: loginFlowSchema,
})
export const providerClient = {
  getStatus: () => transport.request('/v1/provider/status', { schema: providerStatusSchema }),
  configure: (model: string, providerId?: 'codex' | 'opencode') => mutate('configure', { model, ...(providerId ? { providerId } : {}) }),
  verify: () => mutate('verify'),
  disconnect: () => mutate('disconnect'),
  login: () => mutateLoginFlow('login'),
  getLogin: () => transport.request('/v1/provider/login', { schema: loginFlowSchema }),
  cancelLogin: () => mutateLoginFlow('login/cancel'),
  logout: () => transport.request('/v1/provider/logout', {
    method: 'POST', mutation: true, body: {}, schema: providerStatusSchema,
  }),
}
