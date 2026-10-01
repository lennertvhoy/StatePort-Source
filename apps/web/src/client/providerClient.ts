import { z } from 'zod'
import { HttpTransport } from './http/transport'

// Fixed, documented OpenCode credential providers. Each id maps to one
// provider environment variable that StatePort injects into managed OpenCode
// invocations; the list is intentionally closed so an unknown id is refused.
export const OPENCODE_CREDENTIAL_PROVIDERS = [
  'anthropic', 'openai', 'openrouter', 'google', 'groq', 'xai',
] as const
export type OpenCodeCredentialProvider = (typeof OPENCODE_CREDENTIAL_PROVIDERS)[number]
export const OPENCODE_CREDENTIAL_PROVIDER_LABELS: Record<OpenCodeCredentialProvider, string> = {
  anthropic: 'Anthropic', openai: 'OpenAI', openrouter: 'OpenRouter',
  google: 'Google (Gemini)', groq: 'Groq', xai: 'xAI',
}

export const providerStatusSchema = z.object({
  configured: z.boolean(), executableInstalled: z.boolean(), connected: z.boolean(),
  model: z.string().nullable(),
  providerId: z.enum(['codex', 'opencode']).optional(),
  executableStatus: z.enum(['unverified', 'installed', 'missing']).optional(),
  executableVersion: z.string().nullable().optional(),
  executionRefusal: z.string().nullable().optional(),
  authenticationStatus: z.enum(['unverified', 'authenticated', 'unauthenticated', 'unavailable']),
  requestStatus: z.enum(['unverified', 'succeeded', 'failed']),
  telemetryStatus: z.literal('unavailable'), detail: z.string(),
  credentialStatus: z.enum(['configured', 'unconfigured']).optional(),
  credentialProvider: z.enum(OPENCODE_CREDENTIAL_PROVIDERS).nullable().optional(),
  credentialEnvVar: z.string().nullable().optional(),
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
  setCredential: (provider: OpenCodeCredentialProvider, apiKey: string) => mutate('credential', { provider, apiKey }),
  removeCredential: (provider: OpenCodeCredentialProvider) => mutate('credential/remove', { provider }),
  login: () => mutateLoginFlow('login'),
  getLogin: () => transport.request('/v1/provider/login', { schema: loginFlowSchema }),
  cancelLogin: () => mutateLoginFlow('login/cancel'),
  logout: () => transport.request('/v1/provider/logout', {
    method: 'POST', mutation: true, body: {}, schema: providerStatusSchema,
  }),
}
