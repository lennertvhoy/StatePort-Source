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
const transport = new HttpTransport()
const mutate = (action: string, body: object = {}) => transport.request(`/v1/provider/${action}`, {
  method: 'POST', mutation: true, body, schema: providerStatusSchema,
})
export const providerClient = {
  getStatus: () => transport.request('/v1/provider/status', { schema: providerStatusSchema }),
  configure: (model: string, providerId?: 'codex' | 'opencode') => mutate('configure', { model, ...(providerId ? { providerId } : {}) }),
  verify: () => mutate('verify'),
  disconnect: () => mutate('disconnect'),
}
