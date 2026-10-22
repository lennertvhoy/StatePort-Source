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
  // Adopted OpenCode sign-in: presence, timestamp, source path and provider
  // names only. The service never returns, and this client never holds, a value.
  adoptionStatus: z.enum(['adopted', 'not_adopted']).optional(),
  adoptionSourceAvailable: z.boolean().optional(),
  adoptedAt: z.string().nullable().optional(),
  adoptedSource: z.string().nullable().optional(),
  adoptedProviders: z.array(z.string()).optional(),
  adoptionSourceProviders: z.array(z.string()).optional(),
})
export type ProviderStatus = z.infer<typeof providerStatusSchema>
const transport = new HttpTransport()
const mutate = (action: string, body: object = {}) => transport.request(`/v1/provider/${action}`, {
  method: 'POST', mutation: true, body, schema: providerStatusSchema,
})
export const providerClient = {
  getStatus: () => transport.request('/v1/provider/status', { schema: providerStatusSchema }),
  // OpenCode is the only provider this release offers. A status may still
  // report another saved provider (an older install); saving a model here
  // always selects OpenCode.
  configure: (model: string) => mutate('configure', { model, providerId: 'opencode' }),
  verify: () => mutate('verify'),
  disconnect: () => mutate('disconnect'),
  setCredential: (provider: OpenCodeCredentialProvider, apiKey: string) => mutate('credential', { provider, apiKey }),
  removeCredential: (provider: OpenCodeCredentialProvider) => mutate('credential/remove', { provider }),
  adoptSignIn: (providers?: string[]) => mutate('adopt', providers && providers.length > 0 ? { providers } : {}),
  removeAdoptedSignIn: () => mutate('adopt/remove'),
}
