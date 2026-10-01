/**
 * Wire-contract tests for the integrated provider device-login client
 * methods: exact paths, methods, empty-body POSTs with the CSRF mutation
 * header, envelope handling, and strict flow-schema validation.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

import { loginFlowSchema, providerClient } from '../../providerClient'
import { jsonResponse, makeFakeFetch } from './helpers'

const flow = {
  active: true,
  phase: 'code' as const,
  verificationUrl: 'https://example.com/device',
  userCode: 'WDJB-MJHT',
  detail: 'Open the link and enter the code.',
}

describe('provider device-login wire contract', () => {
  afterEach(() => { vi.unstubAllGlobals() })

  it('starts the flow with POST /v1/provider/login, empty body and CSRF mutation header', async () => {
    const fake = makeFakeFetch([['POST', '/v1/provider/login', jsonResponse({ ok: true, result: flow })]])
    vi.stubGlobal('fetch', fake.fetchFn)
    await expect(providerClient.login()).resolves.toEqual(flow)
    const call = fake.callsTo('/v1/provider/login')[0]
    expect(call.method).toBe('POST')
    expect(call.body).toEqual({})
    expect(call.headers['x-stateport-csrf']).toBe('test-csrf')
  })

  it('observes the flow with GET /v1/provider/login', async () => {
    const fake = makeFakeFetch([['GET', '/v1/provider/login', jsonResponse(flow)]])
    vi.stubGlobal('fetch', fake.fetchFn)
    await expect(providerClient.getLogin()).resolves.toEqual(flow)
    expect(fake.callsTo('/v1/provider/login').map(call => call.method)).toEqual(['GET'])
  })

  it('cancels with POST /v1/provider/login/cancel and an empty body', async () => {
    const cancelled = { ...flow, active: false, phase: 'cancelled' as const, verificationUrl: null, userCode: null }
    const fake = makeFakeFetch([['POST', '/v1/provider/login/cancel', jsonResponse({ ok: true, result: cancelled })]])
    vi.stubGlobal('fetch', fake.fetchFn)
    await expect(providerClient.cancelLogin()).resolves.toEqual(cancelled)
    const call = fake.callsTo('/v1/provider/login/cancel')[0]
    expect(call.method).toBe('POST')
    expect(call.body).toEqual({})
    expect(call.headers['x-stateport-csrf']).toBe('test-csrf')
  })

  it('rejects a flow payload with an unknown phase', async () => {
    const fake = makeFakeFetch([['GET', '/v1/provider/login', jsonResponse({ ...flow, phase: 'surprise' })]])
    vi.stubGlobal('fetch', fake.fetchFn)
    await expect(providerClient.getLogin()).rejects.toThrow('Response failed validation')
  })

  it('surfaces the provider_login_active error code from the error envelope', async () => {
    const fake = makeFakeFetch([['POST', '/v1/provider/login', jsonResponse({ ok: false, error: { code: 'provider_login_active', message: 'A device sign-in is already active' } }, 409)]])
    vi.stubGlobal('fetch', fake.fetchFn)
    await expect(providerClient.login()).rejects.toMatchObject({ code: 'provider_login_active', status: 409 })
  })

  it('signs out with POST /v1/provider/logout returning ProviderStatus', async () => {
    const signedOut = {
      configured: true, executableInstalled: true, connected: false, model: null,
      authenticationStatus: 'unauthenticated', requestStatus: 'unverified',
      telemetryStatus: 'unavailable', detail: 'Signed out.',
    }
    const fake = makeFakeFetch([['POST', '/v1/provider/logout', jsonResponse({ ok: true, result: signedOut })]])
    vi.stubGlobal('fetch', fake.fetchFn)
    await expect(providerClient.logout()).resolves.toEqual(signedOut)
    const call = fake.callsTo('/v1/provider/logout')[0]
    expect(call.method).toBe('POST')
    expect(call.body).toEqual({})
  })

  it('validates the login flow schema shape', () => {
    expect(loginFlowSchema.safeParse(flow).success).toBe(true)
    expect(loginFlowSchema.safeParse({ ...flow, verificationUrl: null, userCode: null, phase: 'pending' }).success).toBe(true)
    expect(loginFlowSchema.safeParse({ ...flow, phase: 'unknown' }).success).toBe(false)
    expect(loginFlowSchema.safeParse({ ...flow, userCode: 42 }).success).toBe(false)
    expect(loginFlowSchema.safeParse({ ...flow, detail: undefined }).success).toBe(false)
  })
})
