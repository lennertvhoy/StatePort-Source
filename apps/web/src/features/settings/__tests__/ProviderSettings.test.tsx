import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ProviderSettings } from '../ProviderSettings'
import { providerClient, type ProviderStatus } from '@/client/providerClient'
import { useSessionStore } from '@/state'
import { ClientError } from '@/client/types'
vi.mock('@/client/providerClient', () => ({
  OPENCODE_CREDENTIAL_PROVIDERS: ['anthropic', 'openai', 'openrouter', 'google', 'groq', 'xai'],
  OPENCODE_CREDENTIAL_PROVIDER_LABELS: { anthropic: 'Anthropic', openai: 'OpenAI', openrouter: 'OpenRouter', google: 'Google (Gemini)', groq: 'Groq', xai: 'xAI' },
  providerClient: { getStatus: vi.fn(), configure: vi.fn(), verify: vi.fn(), disconnect: vi.fn(), setCredential: vi.fn(), removeCredential: vi.fn(), adoptSignIn: vi.fn(), removeAdoptedSignIn: vi.fn() },
}))
const status: ProviderStatus = { configured: false, executableInstalled: false, connected: false, model: null, providerId: 'opencode', authenticationStatus: 'unavailable', requestStatus: 'unverified', telemetryStatus: 'unavailable', detail: 'OpenCode is missing in this runtime.' }
const operatorSession = { state: 'connected' as const, endpoint: '', actor: { role: 'platform_operator' as const, actorId: 'operator', platformOperationsAllowed: true, statebenchInspectionAllowed: false } }
afterEach(() => { cleanup(); Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1024 }) })
describe('Provider settings', () => {
  beforeEach(() => { useSessionStore.setState({ serviceStatus: operatorSession }); vi.resetAllMocks(); vi.mocked(providerClient.getStatus).mockResolvedValue(status) })

  it('separates missing executable, configuration and request proof without a credential field in the model form', async () => {
    render(<ProviderSettings />)
    expect(await screen.findByText('OpenCode is missing in this runtime.')).not.toBeNull()
    expect((screen.getByRole('button', { name: 'Check selected adapter' }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByRole('textbox', { name: 'OpenCode model identifier' }).getAttribute('autoComplete')).toBe('off')
    expect(screen.getByText('OpenCode', { selector: 'dd' })).not.toBeNull()
  })

  it('offers no Codex provider, device sign-in, sign-out or login command', async () => {
    vi.mocked(providerClient.getStatus).mockResolvedValue({ ...status, configured: true, connected: true, model: 'opencode/test', executableInstalled: true })
    render(<ProviderSettings />)
    await screen.findByDisplayValue('opencode/test')
    expect(screen.queryByRole('combobox', { name: 'Coding provider' })).toBeNull()
    expect(document.getElementById('provider-choice')).toBeNull()
    expect(document.body.textContent ?? '').not.toMatch(/codex|device sign-in|one-time code|stateport_codex/i)
    for (const name of [/device sign-in/i, /sign out/i, /login command/i]) {
      expect(screen.queryByRole('button', { name })).toBeNull()
    }
  })

  it('says plainly that a different saved provider is not available and keeps the adapter check off until OpenCode is saved', async () => {
    vi.mocked(providerClient.getStatus).mockResolvedValue({ ...status, providerId: 'codex', configured: true, connected: true, model: 'gpt-x', executableInstalled: true })
    render(<ProviderSettings />)
    await screen.findByDisplayValue('gpt-x')
    expect(screen.getByText(/different AI provider saved, and this release does not offer it/)).toBeTruthy()
    expect(screen.getByText('Not available in this release', { selector: 'dd' })).toBeTruthy()
    expect((screen.getByRole('button', { name: 'Check selected adapter' }) as HTMLButtonElement).disabled).toBe(true)
    // Saving a model selects OpenCode.
    vi.mocked(providerClient.configure).mockResolvedValue({ ...status, configured: true, connected: true, model: 'opencode/test', executableInstalled: true, detail: 'Saved OpenCode selection.' })
    const user = userEvent.setup()
    await user.clear(screen.getByRole('textbox', { name: 'OpenCode model identifier' }))
    await user.type(screen.getByRole('textbox', { name: 'OpenCode model identifier' }), 'opencode/test')
    await user.click(screen.getByRole('button', { name: 'Save model and enable' }))
    expect(providerClient.configure).toHaveBeenCalledExactlyOnceWith('opencode/test')
    await screen.findByText('Saved OpenCode selection.')
    expect(screen.queryByText(/different AI provider saved/)).toBeNull()
  })

  it('saves only model metadata, checks explicitly and disconnects', async () => {
    const user = userEvent.setup()
    const configured = { ...status, configured: true, executableInstalled: true, executableStatus: 'installed' as const, connected: true, model: 'test-model', authenticationStatus: 'unverified' as const }
    vi.mocked(providerClient.configure).mockResolvedValue(configured)
    vi.mocked(providerClient.verify).mockResolvedValue({ ...configured, authenticationStatus: 'authenticated', requestStatus: 'succeeded' })
    vi.mocked(providerClient.disconnect).mockResolvedValue({ ...configured, connected: false })
    render(<ProviderSettings />)
    await screen.findByText('OpenCode is missing in this runtime.')
    await user.type(screen.getByRole('textbox', { name: 'OpenCode model identifier' }), 'test-model')
    await user.click(screen.getByRole('button', { name: 'Save model and enable' }))
    expect(providerClient.configure).toHaveBeenCalledExactlyOnceWith('test-model')
    expect(providerClient.verify).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Check selected adapter' }))
    expect(await screen.findByText('Present (expiry not guaranteed)')).not.toBeNull()
    await user.click(screen.getByRole('button', { name: 'Disconnect StatePort' }))
    await waitFor(() => expect(screen.getByText('Disconnected')).toBeTruthy())
  })

  it.each([
    { executableInstalled: true, executableStatus: 'installed' as const, requestStatus: 'unverified' as const, title: 'Adapter check passed', detail: 'OpenCode executable verified in this runtime.' },
    { executableInstalled: false, executableStatus: 'missing' as const, requestStatus: 'failed' as const, title: 'Adapter check failed', detail: 'OpenCode executable is missing in this runtime.' },
    { executableInstalled: true, executableStatus: 'installed' as const, requestStatus: 'failed' as const, title: 'Adapter check failed', detail: 'OpenCode did not answer the version probe.' },
  ])('shows the returned adapter outcome and reason after verification: $title', async ({ executableInstalled, executableStatus, requestStatus, title, detail }) => {
    const selected: ProviderStatus = { ...status, providerId: 'opencode', configured: true, connected: true, model: 'openai/test', detail: 'Saved OpenCode selection.' }
    vi.mocked(providerClient.getStatus).mockResolvedValue(selected)
    vi.mocked(providerClient.verify).mockResolvedValue({ ...selected, executableInstalled, executableStatus, requestStatus, detail, executionRefusal: executableInstalled ? null : 'The pinned runtime is absent.' })
    render(<ProviderSettings />)
    await screen.findByText('Saved OpenCode selection.')

    await userEvent.click(screen.getByRole('button', { name: 'Check selected adapter' }))

    const outcome = await screen.findByLabelText('Provider check result')
    expect(outcome.textContent).toContain(title)
    expect(outcome.textContent).toContain(detail)
    expect(outcome.textContent).toContain(executableInstalled ? 'Installed' : 'Missing')
    if (!executableInstalled) expect(outcome.textContent).toContain('The pinned runtime is absent.')
    expect(outcome.textContent).toContain('Bounded request: ' + requestStatus)
  })

  it('rejects an invalid model identifier inline before a save request', async () => {
    render(<ProviderSettings />)
    await screen.findByText('OpenCode is missing in this runtime.')
    await userEvent.type(screen.getByRole('textbox', { name: 'OpenCode model identifier' }), 'bad model!')

    expect(screen.getByText(/letters, digits, and \. _ : \/ \+ -/)).toBeTruthy()
    expect(screen.getByRole('textbox', { name: 'OpenCode model identifier' }).getAttribute('aria-invalid')).toBe('true')
    fireEvent.submit(screen.getByRole('form', { name: 'Provider configuration' }))
    expect(providerClient.configure).not.toHaveBeenCalled()
  })

  it.each([
    { message: 'the local operation failed', code: 'operation_failed' },
    { message: 'model is unavailable for this runtime', code: 'provider_model_unavailable' },
  ])('shows the service refusal when a valid model save is rejected: $code', async ({ message, code }) => {
    vi.mocked(providerClient.configure).mockRejectedValue(new ClientError('http', message, { status: 400, code }))
    render(<ProviderSettings />)
    await screen.findByText('OpenCode is missing in this runtime.')
    await userEvent.type(screen.getByRole('textbox', { name: 'OpenCode model identifier' }), 'valid/model-1')

    await userEvent.click(screen.getByRole('button', { name: 'Save model and enable' }))

    expect((await screen.findByRole('alert')).textContent).toContain(message)
    expect(screen.getByRole('alert').textContent).toContain(code)
  })
})

it.each([
  { role: 'local_user' as const, allowed: false, state: 'connected' as const },
  { role: 'platform_operator' as const, allowed: false, state: 'connected' as const },
  { role: 'platform_operator' as const, allowed: true, state: 'offline' as const },
])('keeps observations readable but refuses changes for $role / $allowed / $state', async ({ role, allowed, state }) => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: { state, endpoint: '', actor: { role, actorId: 'test', platformOperationsAllowed: allowed, statebenchInspectionAllowed: false } } })
  vi.mocked(providerClient.getStatus).mockResolvedValue({ ...status, configured: true, executableInstalled: true, connected: true, model: 'existing-model' })
  const view = render(<ProviderSettings />)
  await screen.findByDisplayValue('existing-model')
  expect(screen.getByText(/opening this page does not grant permission/)).toBeTruthy()
  for (const name of ['Save model and enable', 'Check selected adapter', 'Disconnect StatePort']) {
    expect((screen.getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(true)
  }
  fireEvent.submit(screen.getByRole('form', { name: 'Provider configuration' }))
  expect(providerClient.configure).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
  await waitFor(() => expect(providerClient.getStatus).toHaveBeenCalledTimes(2))
  view.unmount()
})

it('explains a server-side authorization refusal without exposing its raw text', async () => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: operatorSession })
  vi.mocked(providerClient.getStatus).mockResolvedValue({ ...status, configured: true, executableInstalled: true, connected: true, model: 'existing-model' })
  vi.mocked(providerClient.verify).mockRejectedValue(new ClientError('unavailable', 'private internal diagnostic', { status: 403 }))
  const user = userEvent.setup()
  const view = render(<ProviderSettings />)
  await screen.findByDisplayValue('existing-model')
  await user.click(screen.getByRole('button', { name: 'Check selected adapter' }))
  expect((await screen.findByRole('alert')).textContent).toContain('authorized platform operator session')
  expect(screen.queryByText('private internal diagnostic')).toBeNull()
  view.unmount()
})

it('provides labelled keyboard form controls without nested main landmarks at a narrow viewport', async () => {
  vi.resetAllMocks()
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: 360 })
  useSessionStore.setState({ serviceStatus: operatorSession })
  vi.mocked(providerClient.getStatus).mockResolvedValue(status)
  const user = userEvent.setup()
  const view = render(<main><ProviderSettings /></main>)
  await screen.findByText('OpenCode is missing in this runtime.')
  await user.tab()
  expect(document.activeElement).toBe(screen.getByRole('textbox', { name: 'OpenCode model identifier' }))
  expect(document.activeElement?.getAttribute('aria-describedby')).toBe('provider-model-help')
  expect(screen.getAllByRole('main')).toHaveLength(1)
  await user.type(screen.getByRole('textbox', { name: 'OpenCode model identifier' }), 'test-model')
  await user.tab()
  expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Save model and enable' }))
  view.unmount()
})

it('saves OpenCode as the actual enabled selection and retains it after reopening', async () => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: operatorSession })
  const selected: ProviderStatus = {
    ...status, providerId: 'opencode', configured: true, connected: true, model: 'opencode/test',
    executableInstalled: true, executableStatus: 'installed', executableVersion: '1.18.31', authenticationStatus: 'unverified',
    detail: 'OpenCode model saved. StatePort runs the pinned OpenCode executable and reports it; it does not verify or store OpenCode authentication. Sign in with OpenCode itself, then send conversation work.',
  }
  vi.mocked(providerClient.getStatus).mockResolvedValueOnce(status).mockResolvedValue({ ...selected, executableStatus: 'unverified' })
  vi.mocked(providerClient.configure).mockResolvedValue(selected)
  vi.mocked(providerClient.verify).mockResolvedValue({ ...selected, requestStatus: 'failed' })
  const user = userEvent.setup()
  const view = render(<ProviderSettings />)
  await screen.findByRole('textbox', { name: 'OpenCode model identifier' })
  await user.type(screen.getByRole('textbox', { name: 'OpenCode model identifier' }), 'opencode/test')
  await user.click(screen.getByRole('button', { name: 'Save model and enable' }))
  expect(providerClient.configure).toHaveBeenCalledExactlyOnceWith('opencode/test')
  expect(await screen.findByText(selected.detail)).not.toBeNull()
  expect(screen.getByText('Installed (1.18.31)')).not.toBeNull()
  expect(screen.getByText('Enabled')).not.toBeNull()
  await user.click(screen.getByRole('button', { name: 'Check selected adapter' }))
  expect(providerClient.verify).toHaveBeenCalledTimes(1)
  expect(await screen.findByText('failed')).not.toBeNull()
  view.unmount()
  render(<ProviderSettings />)
  await waitFor(() => expect((screen.getByRole('textbox', { name: 'OpenCode model identifier' }) as HTMLInputElement).value).toBe('opencode/test'))
  expect(screen.getByText('Not checked in this service session')).not.toBeNull()
  expect(providerClient.configure).toHaveBeenCalledTimes(1)
})

it.each([true, false])('preserves a draft and newer saved status when initial status arrives before save=%s', async (beforeSave) => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: operatorSession })
  let resolveInitial!: (value: ProviderStatus) => void
  vi.mocked(providerClient.getStatus).mockReturnValueOnce(new Promise(resolve => { resolveInitial = resolve }))
  const selected: ProviderStatus = { ...status, providerId: 'opencode', configured: true, model: 'openai/test-model', detail: 'Selected OpenCode result' }
  vi.mocked(providerClient.configure).mockResolvedValue(selected)
  const user = userEvent.setup()
  render(<ProviderSettings />)
  await user.type(screen.getByRole('textbox', { name: 'OpenCode model identifier' }), 'openai/test-model')
  if (beforeSave) {
    await act(async () => resolveInitial(status))
    expect((screen.getByRole('textbox', { name: 'OpenCode model identifier' }) as HTMLInputElement).value).toBe('openai/test-model')
    vi.mocked(providerClient.getStatus).mockResolvedValue(status)
    await user.click(screen.getByRole('button', { name: 'Refresh status' }))
    expect((screen.getByRole('textbox', { name: 'OpenCode model identifier' }) as HTMLInputElement).value).toBe('openai/test-model')
  }
  await user.click(screen.getByRole('button', { name: 'Save model and enable' }))
  await screen.findByText('Selected OpenCode result')
  if (!beforeSave) await act(async () => resolveInitial(status))
  expect(screen.getByText('Selected OpenCode result')).toBeTruthy()
  expect(providerClient.configure).toHaveBeenCalledExactlyOnceWith('openai/test-model')
})

it('connects and removes an operator OpenCode credential without re-displaying the key', async () => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: operatorSession })
  const selected: ProviderStatus = {
    ...status, providerId: 'opencode', configured: true, connected: true, model: 'openai/test',
    executableInstalled: true, executableStatus: 'installed', authenticationStatus: 'unverified',
    credentialStatus: 'unconfigured', credentialProvider: null, credentialEnvVar: null,
  }
  vi.mocked(providerClient.getStatus).mockResolvedValue(selected)
  vi.mocked(providerClient.setCredential).mockResolvedValue({
    ...selected, credentialStatus: 'configured', credentialProvider: 'google', credentialEnvVar: 'GEMINI_API_KEY',
  })
  vi.mocked(providerClient.removeCredential).mockResolvedValue({
    ...selected, credentialStatus: 'unconfigured', credentialProvider: null, credentialEnvVar: null,
  })
  const user = userEvent.setup()
  const view = render(<ProviderSettings />)
  await screen.findByRole('combobox', { name: 'OpenCode provider' })
  expect(screen.getByText('No credential.')).toBeTruthy()
  const providerSelect = screen.getByRole('combobox', { name: 'OpenCode provider' }) as HTMLSelectElement
  expect(Array.from(providerSelect.options).map(option => option.value)).toEqual(['anthropic', 'openai', 'openrouter', 'google', 'groq', 'xai'])
  await user.selectOptions(providerSelect, 'google')
  const keyField = screen.getByLabelText('Provider API key') as HTMLInputElement
  expect(keyField.getAttribute('type')).toBe('password')
  await user.type(keyField, 'AIza-fake-browser')
  await user.click(screen.getByRole('button', { name: 'Connect API key' }))
  expect(providerClient.setCredential).toHaveBeenCalledExactlyOnceWith('google', 'AIza-fake-browser')
  expect(await screen.findByText(/Credential configured for Google \(Gemini\)/)).toBeTruthy()
  // The key field clears after submit and the value is never re-displayed.
  expect((screen.getByLabelText('Provider API key') as HTMLInputElement).value).toBe('')
  expect(screen.queryByDisplayValue('AIza-fake-browser')).toBeNull()
  await user.click(screen.getByRole('button', { name: 'Remove credential' }))
  expect(providerClient.removeCredential).toHaveBeenCalledExactlyOnceWith('google')
  expect(await screen.findByText('No credential.')).toBeTruthy()
  view.unmount()
})

it('refuses OpenCode credential controls without an operator session', async () => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'local_user', actorId: 'user', platformOperationsAllowed: false, statebenchInspectionAllowed: false } } })
  vi.mocked(providerClient.getStatus).mockResolvedValue({ ...status, providerId: 'opencode', configured: true, model: 'openai/test' })
  const view = render(<ProviderSettings />)
  await screen.findByRole('combobox', { name: 'OpenCode provider' })
  expect((screen.getByLabelText('Provider API key') as HTMLInputElement).disabled).toBe(true)
  expect((screen.getByRole('button', { name: 'Connect API key' }) as HTMLButtonElement).disabled).toBe(true)
  expect((screen.getByRole('button', { name: 'Remove credential' }) as HTMLButtonElement).disabled).toBe(true)
  fireEvent.submit(screen.getByRole('form', { name: 'OpenCode credential' }))
  expect(providerClient.setCredential).not.toHaveBeenCalled()
  expect(providerClient.removeCredential).not.toHaveBeenCalled()
  view.unmount()
})

it('enables provider changes for a local user whose backend grants the provider permission', async () => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'local_user', actorId: 'local-user', platformOperationsAllowed: false, statebenchInspectionAllowed: false, providerActionsAllowed: true } } })
  vi.mocked(providerClient.getStatus).mockResolvedValue({ ...status, configured: true, executableInstalled: true, connected: true, model: 'existing-model' })
  const view = render(<ProviderSettings />)
  await screen.findByDisplayValue('existing-model')
  expect(screen.queryByText(/opening this page does not grant permission/)).toBeNull()
  expect((screen.getByRole('button', { name: 'Disconnect StatePort' }) as HTMLButtonElement).disabled).toBe(false)
  view.unmount()
})

it('keeps provider changes refused when the backend withholds the provider permission', async () => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'platform_operator', actorId: 'operator', platformOperationsAllowed: true, statebenchInspectionAllowed: false, providerActionsAllowed: false } } })
  vi.mocked(providerClient.getStatus).mockResolvedValue({ ...status, configured: true, executableInstalled: true, connected: true, model: 'existing-model' })
  const view = render(<ProviderSettings />)
  await screen.findByDisplayValue('existing-model')
  expect((screen.getByRole('button', { name: 'Disconnect StatePort' }) as HTMLButtonElement).disabled).toBe(true)
  view.unmount()
})

describe('Existing OpenCode sign-in adoption', () => {
  const base: ProviderStatus = {
    ...status, providerId: 'opencode', configured: true, connected: true, model: 'opencode-go/glm-5',
    executableInstalled: true, executableStatus: 'installed', authenticationStatus: 'unverified',
    credentialStatus: 'unconfigured', credentialProvider: null, credentialEnvVar: null,
    adoptionStatus: 'not_adopted', adoptionSourceAvailable: true, adoptedAt: null, adoptedSource: null, adoptedProviders: [],
  }
  const adopted: ProviderStatus = {
    ...base, adoptionStatus: 'adopted', adoptionSourceAvailable: false,
    adoptedAt: '2026-10-01T12:00:00Z', adoptedSource: '/home/operator/.local/share/opencode/auth.json', adoptedProviders: ['opencode-go'],
  }
  beforeEach(() => { vi.resetAllMocks(); useSessionStore.setState({ serviceStatus: operatorSession }) })

  it('says which providers will be copied and warns about OAuth refresh-token rotation', async () => {
    vi.mocked(providerClient.getStatus).mockResolvedValue({ ...base, adoptionSourceProviders: ['openai', 'opencode-go'] })
    render(<ProviderSettings />)
    const state = await screen.findByRole('status', { name: 'Adopted sign-in state' })
    expect(state.textContent).toContain('Providers found: openai, opencode-go')
    expect(state.textContent).toMatch(/only the one matching your saved model/)
    const section = screen.getByRole('region', { name: 'Existing OpenCode sign-in' })
    expect(section.textContent).toMatch(/Other providers in the file are never copied/)
    expect(section.textContent).toMatch(/OAuth sign-in rotates its refresh token.*sign the original OpenCode out/)
  })

  it('walks not adopted, adopted and removed with honest presence-only text', async () => {
    vi.mocked(providerClient.getStatus).mockResolvedValue(base)
    vi.mocked(providerClient.adoptSignIn).mockResolvedValue(adopted)
    vi.mocked(providerClient.removeAdoptedSignIn).mockResolvedValue({ ...base, adoptionSourceAvailable: true })
    const user = userEvent.setup()
    const view = render(<ProviderSettings />)
    const state = await screen.findByRole('status', { name: 'Adopted sign-in state' })
    expect(state.textContent).toMatch(/Not adopted\. An existing OpenCode sign-in file was found/)
    expect((screen.getByRole('button', { name: 'Remove adopted sign-in' }) as HTMLButtonElement).disabled).toBe(true)
    await user.click(screen.getByRole('button', { name: 'Adopt existing OpenCode sign-in' }))
    expect(providerClient.adoptSignIn).toHaveBeenCalledOnce()
    await waitFor(() => expect(screen.getByRole('status', { name: 'Adopted sign-in state' }).textContent).toMatch(/Adopted: a copy of an existing OpenCode sign-in is present/))
    const text = screen.getByRole('status', { name: 'Adopted sign-in state' }).textContent ?? ''
    expect(text).toContain('/home/operator/.local/share/opencode/auth.json')
    expect(text).toContain('providers: opencode-go')
    expect(text).toMatch(/Presence only: StatePort does not check that it is still valid/)
    await user.click(screen.getByRole('button', { name: 'Remove adopted sign-in' }))
    expect(providerClient.removeAdoptedSignIn).toHaveBeenCalledOnce()
    await waitFor(() => expect(screen.getByRole('status', { name: 'Adopted sign-in state' }).textContent).toMatch(/^Not adopted/))
    view.unmount()
  })

  it('tells the truth when no existing sign-in is available and shows the refusal paths', async () => {
    vi.mocked(providerClient.getStatus).mockResolvedValue({ ...base, adoptionSourceAvailable: false })
    vi.mocked(providerClient.adoptSignIn).mockRejectedValue(new ClientError('http', 'No existing OpenCode sign-in was found. Looked for: /home/operator/.local/share/opencode/auth.json.', { status: 409, code: 'adoption_source_missing' }))
    const user = userEvent.setup()
    const view = render(<ProviderSettings />)
    const state = await screen.findByRole('status', { name: 'Adopted sign-in state' })
    expect(state.textContent).toMatch(/No existing OpenCode sign-in file was found in this runtime/)
    expect(state.textContent).toContain('scripts/adopt_opencode_signin.py')
    await user.click(screen.getByRole('button', { name: 'Adopt existing OpenCode sign-in' }))
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('OpenCode sign-in was not adopted')
    expect(alert.textContent).toContain('/home/operator/.local/share/opencode/auth.json')
    expect(alert.textContent).toContain('adoption_source_missing')
    expect(screen.getByRole('status', { name: 'Adopted sign-in state' }).textContent).toMatch(/^Not adopted/)
    view.unmount()
  })

  it('refuses the adopt controls without provider permission', async () => {
    useSessionStore.setState({ serviceStatus: { ...operatorSession, actor: { ...operatorSession.actor, providerActionsAllowed: false } } })
    vi.mocked(providerClient.getStatus).mockResolvedValue(base)
    const denied = render(<ProviderSettings />)
    const button = await screen.findByRole('button', { name: 'Adopt existing OpenCode sign-in' }) as HTMLButtonElement
    expect(button.disabled).toBe(true)
    expect(providerClient.adoptSignIn).not.toHaveBeenCalled()
    denied.unmount()
  })
})
