/// <reference types="node" />
import { execFileSync, spawnSync } from 'node:child_process'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ProviderSettings } from '../ProviderSettings'
import { providerClient, type LoginFlow, type ProviderStatus } from '@/client/providerClient'
import { useSessionStore } from '@/state'
import { ClientError } from '@/client/types'
vi.mock('@/client/providerClient', () => ({
  OPENCODE_CREDENTIAL_PROVIDERS: ['anthropic', 'openai', 'openrouter', 'google', 'groq', 'xai'],
  OPENCODE_CREDENTIAL_PROVIDER_LABELS: { anthropic: 'Anthropic', openai: 'OpenAI', openrouter: 'OpenRouter', google: 'Google (Gemini)', groq: 'Groq', xai: 'xAI' },
  providerClient: { getStatus: vi.fn(), configure: vi.fn(), verify: vi.fn(), disconnect: vi.fn(), login: vi.fn(), getLogin: vi.fn(), cancelLogin: vi.fn(), logout: vi.fn(), setCredential: vi.fn(), removeCredential: vi.fn(), adoptSignIn: vi.fn(), removeAdoptedSignIn: vi.fn() },
}))
const status: ProviderStatus = { configured: false, executableInstalled: false, connected: false, model: null, providerId: 'codex', authenticationStatus: 'unavailable', requestStatus: 'unverified', telemetryStatus: 'unavailable', detail: 'Codex is missing in this runtime.' }
afterEach(() => { cleanup(); Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1024 }) })
describe('Provider settings', () => {
  beforeEach(() => { useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'platform_operator', actorId: 'operator', platformOperationsAllowed: true, statebenchInspectionAllowed: false } } }); vi.resetAllMocks(); vi.mocked(providerClient.getStatus).mockResolvedValue(status) })
  it('separates missing executable, configuration and request proof without a credential field', async () => {
    render(<ProviderSettings />)
    expect(await screen.findByText('Codex is missing in this runtime.')).not.toBeNull()
    expect((screen.getByRole('button', { name: 'Verify bounded request' }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getAllByRole('textbox')).toHaveLength(1)
    expect(screen.getByRole('textbox', { name: 'Codex model identifier' }).getAttribute('autoComplete')).toBe('off')
  })
  it('defaults to the shipped OpenCode provider when the service reports none', async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- destructured only to omit providerId from the fixture; the binding is the omission, not its value.
    const { providerId: _unused, ...withoutProvider } = status
    vi.mocked(providerClient.getStatus).mockResolvedValue(withoutProvider)
    render(<ProviderSettings />)
    expect(await screen.findByText('Codex is missing in this runtime.')).not.toBeNull()
    expect(screen.getByRole('textbox', { name: 'OpenCode model identifier' })).not.toBeNull()
    expect(screen.getByText('OpenCode', { selector: 'dd' })).not.toBeNull()
    const choice = document.getElementById('provider-choice') as HTMLSelectElement
    expect(choice.value).toBe('opencode')
  })
  it('saves only model metadata, verifies explicitly and disconnects', async () => {
    const user = userEvent.setup()
    const configured = { ...status, configured: true, executableInstalled: true, connected: true, model: 'test-model', authenticationStatus: 'unverified' as const }
    vi.mocked(providerClient.configure).mockResolvedValue(configured)
    vi.mocked(providerClient.verify).mockResolvedValue({ ...configured, authenticationStatus: 'authenticated', requestStatus: 'succeeded' })
    vi.mocked(providerClient.disconnect).mockResolvedValue({ ...configured, connected: false })
    render(<ProviderSettings />)
    await screen.findByText('Codex is missing in this runtime.')
    await user.type(screen.getByRole('textbox'), 'test-model')
    await user.click(screen.getByRole('button', { name: 'Save model and enable' }))
    expect(providerClient.configure).toHaveBeenCalledWith('test-model', 'codex')
    expect(providerClient.verify).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Verify bounded request' }))
    expect(await screen.findByText('Present (expiry not guaranteed)')).not.toBeNull()
    await user.click(screen.getByRole('button', { name: 'Disconnect StatePort' }))
    await waitFor(() => expect((screen.getByRole('button', { name: 'Verify bounded request' }) as HTMLButtonElement).disabled).toBe(true))
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
    await screen.findByText('Codex is missing in this runtime.')
    await userEvent.type(screen.getByRole('textbox', { name: 'Codex model identifier' }), 'bad model!')

    expect(screen.getByText(/letters, digits, and \. _ : \/ \+ -/)).toBeTruthy()
    expect(screen.getByRole('textbox', { name: 'Codex model identifier' }).getAttribute('aria-invalid')).toBe('true')
    fireEvent.submit(screen.getByRole('form', { name: 'Provider configuration' }))
    expect(providerClient.configure).not.toHaveBeenCalled()
  })

  it.each([
    { message: 'the local operation failed', code: 'operation_failed' },
    { message: 'model is unavailable for this runtime', code: 'provider_model_unavailable' },
  ])('shows the service refusal when a valid model save is rejected: $code', async ({ message, code }) => {
    vi.mocked(providerClient.configure).mockRejectedValue(new ClientError('http', message, { status: 400, code }))
    render(<ProviderSettings />)
    await screen.findByText('Codex is missing in this runtime.')
    await userEvent.type(screen.getByRole('textbox', { name: 'Codex model identifier' }), 'valid/model-1')

    await userEvent.click(screen.getByRole('button', { name: 'Save model and enable' }))

    expect((await screen.findByRole('alert')).textContent).toContain(message)
    expect(screen.getByRole('alert').textContent).toContain(code)
  })

  afterEach(() => { vi.useRealTimers() })

  const codeFlow: LoginFlow = { active: true, phase: 'code', verificationUrl: 'https://example.com/device', userCode: 'WDJB-MJHT', detail: 'Open the link and enter the code.' }
  const authedFlow: LoginFlow = { active: false, phase: 'authenticated', verificationUrl: null, userCode: null, detail: 'Sign-in complete.' }
  const expiredFlow: LoginFlow = { active: false, phase: 'expired', verificationUrl: null, userCode: null, detail: 'The one-time code expired.' }
  const cancelledFlow: LoginFlow = { active: false, phase: 'cancelled', verificationUrl: null, userCode: null, detail: 'Cancelled by the operator.' }
  const pendingFlow: LoginFlow = { active: true, phase: 'pending', verificationUrl: null, userCode: null, detail: 'Waiting for the provider.' }

  it('starts device sign-in, shows the link and copyable code, polls once to authenticated and stops', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    vi.mocked(providerClient.login).mockResolvedValue(codeFlow)
    vi.mocked(providerClient.getLogin).mockResolvedValue(authedFlow)
    const view = render(<ProviderSettings />)
    await act(async () => {})
    expect(screen.getByText('Codex is missing in this runtime.')).toBeTruthy()
    expect(screen.getByText(/No device sign-in is running/)).toBeTruthy()
    await user.click(screen.getByRole('button', { name: 'Start device sign-in' }))
    await act(async () => {})
    expect(screen.getByRole('link', { name: 'https://example.com/device' })).toBeTruthy()
    const codeElement = screen.getByText('WDJB-MJHT')
    expect(codeElement.tagName).toBe('CODE')
    expect(codeElement.className).toContain('select-text')
    expect(screen.getByRole('button', { name: 'Copy one-time code' })).toBeTruthy()
    expect(providerClient.getLogin).not.toHaveBeenCalled()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    try {
      await user.click(screen.getByRole('button', { name: 'Copy one-time code' }))
      expect(writeText).toHaveBeenCalledWith('WDJB-MJHT')
    } finally {
      delete (navigator as { clipboard?: unknown }).clipboard
    }
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(providerClient.getLogin).toHaveBeenCalledTimes(1)
    expect(screen.getByText(/Device sign-in confirmed/)).toBeTruthy()
    await act(async () => { await vi.advanceTimersByTimeAsync(12000) })
    expect(providerClient.getLogin).toHaveBeenCalledTimes(1)
    view.unmount()
  })

  it('surfaces the expired phase and offers a restart', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    vi.mocked(providerClient.login).mockResolvedValue(codeFlow)
    vi.mocked(providerClient.getLogin).mockResolvedValue(expiredFlow)
    const view = render(<ProviderSettings />)
    await act(async () => {})
    await user.click(screen.getByRole('button', { name: 'Start device sign-in' }))
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(screen.getByText(/expired before the sign-in completed/)).toBeTruthy()
    expect(screen.queryByText('WDJB-MJHT')).toBeNull()
    expect((screen.getByRole('button', { name: 'Start device sign-in' }) as HTMLButtonElement).disabled).toBe(false)
    view.unmount()
  })

  it('cancels the active flow, reports cancellation and stops polling', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    vi.mocked(providerClient.login).mockResolvedValue(codeFlow)
    vi.mocked(providerClient.cancelLogin).mockResolvedValue(cancelledFlow)
    const view = render(<ProviderSettings />)
    await act(async () => {})
    await user.click(screen.getByRole('button', { name: 'Start device sign-in' }))
    await act(async () => {})
    expect(screen.getByText(/Open the verification link/)).toBeTruthy()
    await user.click(screen.getByRole('button', { name: 'Cancel device sign-in' }))
    await act(async () => {})
    expect(screen.getByText(/was cancelled/)).toBeTruthy()
    await act(async () => { await vi.advanceTimersByTimeAsync(9000) })
    expect(providerClient.getLogin).not.toHaveBeenCalled()
    view.unmount()
  })

  it('surfaces a double start as an already-active sign-in and adopts the running flow', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    vi.mocked(providerClient.login).mockRejectedValue(new ClientError('http', 'A device sign-in is already active', { status: 409, code: 'provider_login_active' }))
    vi.mocked(providerClient.getLogin).mockResolvedValue(codeFlow)
    const view = render(<ProviderSettings />)
    await act(async () => {})
    await user.click(screen.getByRole('button', { name: 'Start device sign-in' }))
    await act(async () => {})
    expect(screen.getByRole('alert').textContent).toContain('already active')
    expect(screen.getByText('WDJB-MJHT')).toBeTruthy()
    view.unmount()
  })

  it('signs out only after confirmation, then refreshes provider status', async () => {
    const user = userEvent.setup()
    const signedIn = { ...status, configured: true, executableInstalled: true, connected: true, model: 'test-model', authenticationStatus: 'authenticated' as const }
    vi.mocked(providerClient.getStatus).mockResolvedValue(signedIn)
    vi.mocked(providerClient.logout).mockResolvedValue({ ...signedIn, connected: false, authenticationStatus: 'unauthenticated' as const })
    const view = render(<ProviderSettings />)
    await screen.findByText('Present (expiry not guaranteed)')
    await user.click(screen.getByRole('button', { name: 'Sign out of Codex' }))
    expect(providerClient.logout).not.toHaveBeenCalled()
    expect(await screen.findByRole('alertdialog')).toBeTruthy()
    expect(screen.getByText(/separate from Disconnect StatePort/)).toBeTruthy()
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(providerClient.logout).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Sign out of Codex' }))
    await screen.findByRole('alertdialog')
    await user.click(screen.getByRole('button', { name: 'Confirm sign-out' }))
    await waitFor(() => expect(providerClient.logout).toHaveBeenCalledTimes(1))
    expect(await screen.findByText('Disconnected')).toBeTruthy()
    view.unmount()
  })

  it('refuses device sign-in controls without an operator session', async () => {
    vi.resetAllMocks()
    useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'local_user', actorId: 'user', platformOperationsAllowed: false, statebenchInspectionAllowed: false } } })
    vi.mocked(providerClient.getStatus).mockResolvedValue(status)
    const view = render(<ProviderSettings />)
    await screen.findByText('Codex is missing in this runtime.')
    expect((screen.getByRole('button', { name: 'Start device sign-in' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: 'Sign out of Codex' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'Start device sign-in' }))
    await act(async () => {})
    expect(providerClient.login).not.toHaveBeenCalled()
    view.unmount()
  })

  it('hides integrated device sign-in for OpenCode with a fixed explanation', async () => {
    vi.mocked(providerClient.getStatus).mockResolvedValue({ ...status, providerId: 'opencode', configured: true, model: 'opencode/test' })
    const view = render(<ProviderSettings />)
    await screen.findByText(/Integrated device sign-in supports the Codex provider/)
    expect(screen.queryByRole('button', { name: 'Start device sign-in' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Sign out of Codex' })).toBeNull()
    view.unmount()
  })

  it('stops device sign-in polling after unmount', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    vi.mocked(providerClient.login).mockResolvedValue(pendingFlow)
    const view = render(<ProviderSettings />)
    await act(async () => {})
    await user.click(screen.getByRole('button', { name: 'Start device sign-in' }))
    await act(async () => {})
    expect(screen.getByText(/Waiting for Codex to confirm/)).toBeTruthy()
    view.unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(9000) })
    expect(providerClient.getLogin).not.toHaveBeenCalled()
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
  for (const name of ['Save model and enable', 'Verify bounded request', 'Disconnect StatePort']) {
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
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'platform_operator', actorId: 'test', platformOperationsAllowed: true, statebenchInspectionAllowed: false } } })
  vi.mocked(providerClient.getStatus).mockResolvedValue({ ...status, configured: true, executableInstalled: true, connected: true, model: 'existing-model' })
  vi.mocked(providerClient.verify).mockRejectedValue(new ClientError('unavailable', 'private internal diagnostic', { status: 403 }))
  const user = userEvent.setup()
  const view = render(<ProviderSettings />)
  await screen.findByDisplayValue('existing-model')
  await user.click(screen.getByRole('button', { name: 'Verify bounded request' }))
  expect((await screen.findByRole('alert')).textContent).toContain('authorized platform operator session')
  expect(screen.queryByText('private internal diagnostic')).toBeNull()
  view.unmount()
})

it('provides labelled keyboard form controls without nested main landmarks at a narrow viewport', async () => {
  vi.resetAllMocks()
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: 360 })
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'platform_operator', actorId: 'test', platformOperationsAllowed: true, statebenchInspectionAllowed: false } } })
  vi.mocked(providerClient.getStatus).mockResolvedValue(status)
  const user = userEvent.setup()
  const view = render(<main><ProviderSettings /></main>)
  await screen.findByText('Codex is missing in this runtime.')
  await user.tab()
  expect(document.activeElement).toBe(screen.getByRole('combobox', { name: 'Coding provider' }))
  await user.tab()
  expect(document.activeElement).toBe(screen.getByRole('textbox', { name: 'Codex model identifier' }))
  expect(screen.getByRole('textbox').getAttribute('aria-describedby')).toBe('provider-model-help')
  expect(screen.getAllByRole('main')).toHaveLength(1)
  await user.type(screen.getByRole('textbox'), 'test-model')
  await user.tab()
  expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Save model and enable' }))
  view.unmount()
})

it('offers keyboard-readable installed auth instructions without performing authentication', async () => {
  vi.resetAllMocks()
  vi.mocked(providerClient.getStatus).mockResolvedValue(status)
  const user = userEvent.setup()
  render(<ProviderSettings />)
  await screen.findByText('Codex is missing in this runtime.')
  const toggle = screen.getByText('Show installed login command')
  toggle.focus()
  expect(document.activeElement).toBe(toggle)
  await user.keyboard('{Enter}')
  await user.tab()
  expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Select command' }))
  await user.keyboard('{Enter}')
  const command = screen.getByLabelText('Installed Codex login command')
  expect(window.getSelection()?.toString()).toBe(command.textContent)
  const text = command.textContent ?? ''
  expect(() => execFileSync('/bin/bash', ['-n'], { input: text })).not.toThrow()
  expect(text).toContain('label=io.stateport.profile=accepted')
  expect(text).toContain('if [ "${#containers[@]}" -ne 1 ]')
  expect(text).toContain('exec -it --user 65532:65532')
  expect(text).toContain('/usr/bin/env -i')
  expect(text).toContain('CODEX_HOME=/var/lib/stateport-provider/codex')
  expect(text).toContain('login) set -- login --device-auth')
  expect(text).toContain('logout) set -- logout')
  expect(text).toContain('version) set -- --version')
  expect(text).not.toContain('DBUS_SESSION_BUS_ADDRESS')
  expect(text).not.toContain('--privileged')
  expect(providerClient.configure).not.toHaveBeenCalled()
  expect(providerClient.verify).not.toHaveBeenCalled()
  expect(screen.getAllByRole('textbox')).toHaveLength(1)
  expect(screen.getByText(/dedicated private directory outside StatePort application backups/)).toBeTruthy()
})


it.each([
  { inventory: '', exitCode: 0, expectedStatus: 1 },
  { inventory: 'first\nsecond\n', exitCode: 0, expectedStatus: 1 },
  { inventory: 'partial-result\n', exitCode: 125, expectedStatus: 1 },
  { inventory: 'accepted-id\n', exitCode: 0, expectedStatus: 0 },
])('executes only after one successful inventory result ($exitCode, $inventory)', async ({ inventory, exitCode, expectedStatus }) => {
  vi.resetAllMocks()
  vi.mocked(providerClient.getStatus).mockResolvedValue(status)
  render(<ProviderSettings />)
  await screen.findByText('Codex is missing in this runtime.')
  const command = screen.getByLabelText('Installed Codex login command').textContent ?? ''
  // Both host commands are fixture functions. The sudo replacement only
  // returns inventory or prints argv; it never executes Podman or Codex.
  const fixture = `
    id() { printf '%s\\n' 65531; }
    sudo() {
      while [ "$1" != /usr/bin/podman ]; do shift; done
      shift
      if [ "$1" = ps ]; then
        printf '%s' "$FIXTURE_INVENTORY"
        return "$FIXTURE_EXIT"
      fi
      printf 'MOCK_EXEC:%s\\n' "$@"
    }
  `
  const result = spawnSync('/bin/bash', ['--noprofile', '--norc'], {
    input: fixture + command.replace(/stateport_codex login$/, 'stateport_codex version'),
    env: { PATH: '/nonexistent', FIXTURE_INVENTORY: inventory, FIXTURE_EXIT: String(exitCode) },
    encoding: 'utf8',
  })
  expect(result.status).toBe(expectedStatus)
  if (expectedStatus === 0) {
    expect(result.stdout).toContain('MOCK_EXEC:accepted-id')
    expect(result.stdout).toContain('MOCK_EXEC:65532:65532')
    expect(result.stdout).toContain('MOCK_EXEC:CODEX_HOME=/var/lib/stateport-provider/codex')
    expect(result.stdout).toContain('MOCK_EXEC:--version')
    expect(result.stdout).not.toContain('MOCK_EXEC:login')
  } else expect(result.stdout).not.toContain('MOCK_EXEC:')
})

it('saves OpenCode as the actual enabled selection and retains it after reopening', async () => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'platform_operator', actorId: 'operator', platformOperationsAllowed: true, statebenchInspectionAllowed: false } } })
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
  await screen.findByRole('combobox', { name: 'Coding provider' })
  await user.selectOptions(screen.getByRole('combobox', { name: 'Coding provider' }), 'opencode')
  await user.type(screen.getByRole('textbox', { name: 'OpenCode model identifier' }), 'opencode/test')
  await user.click(screen.getByRole('button', { name: 'Save model and enable' }))
  expect(providerClient.configure).toHaveBeenCalledExactlyOnceWith('opencode/test', 'opencode')
  expect(await screen.findByText(selected.detail)).not.toBeNull()
  expect(screen.getByText('Installed (1.18.31)')).not.toBeNull()
  expect(screen.queryByRole('button', { name: 'Show installed login command' })).toBeNull()
  expect(screen.getByText('Enabled')).not.toBeNull()
  await user.click(screen.getByRole('button', { name: 'Check selected adapter' }))
  expect(providerClient.verify).toHaveBeenCalledTimes(1)
  expect(await screen.findByText('failed')).not.toBeNull()
  view.unmount()
  render(<ProviderSettings />)
  await waitFor(() => expect((screen.getByRole('combobox', { name: 'Coding provider' }) as HTMLSelectElement).value).toBe('opencode'))
  expect((screen.getByRole('textbox') as HTMLInputElement).value).toBe('opencode/test')
  expect(screen.getByText('Not checked in this service session')).not.toBeNull()
  expect(providerClient.configure).toHaveBeenCalledTimes(1)
})


it.each([true, false])('preserves a draft and newer saved status when initial status arrives before save=%s', async (beforeSave) => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'platform_operator', actorId: 'operator', platformOperationsAllowed: true, statebenchInspectionAllowed: false } } })
  let resolveInitial!: (value: ProviderStatus) => void
  vi.mocked(providerClient.getStatus).mockReturnValueOnce(new Promise(resolve => { resolveInitial = resolve }))
  const selected: ProviderStatus = { ...status, providerId: 'opencode', configured: true, model: 'openai/test-model', detail: 'Selected OpenCode result' }
  vi.mocked(providerClient.configure).mockResolvedValue(selected)
  const user = userEvent.setup()
  render(<ProviderSettings />)
  await user.selectOptions(screen.getByRole('combobox', { name: 'Coding provider' }), 'opencode')
  await user.type(screen.getByRole('textbox', { name: 'OpenCode model identifier' }), 'openai/test-model')
  if (beforeSave) {
    await act(async () => resolveInitial(status))
    expect((screen.getByRole('textbox', { name: 'OpenCode model identifier' }) as HTMLInputElement).value).toBe('openai/test-model')
    vi.mocked(providerClient.getStatus).mockResolvedValue(status)
    await user.click(screen.getByRole('button', { name: 'Refresh status' }))
    expect((screen.getByRole('combobox', { name: 'Coding provider' }) as HTMLSelectElement).value).toBe('opencode')
    expect((screen.getByRole('textbox') as HTMLInputElement).value).toBe('openai/test-model')
  }
  await user.click(screen.getByRole('button', { name: 'Save model and enable' }))
  await screen.findByText('Selected OpenCode result')
  if (!beforeSave) await act(async () => resolveInitial(status))
  expect(screen.getByText('Selected OpenCode result')).toBeTruthy()
  expect((screen.getByRole('combobox', { name: 'Coding provider' }) as HTMLSelectElement).value).toBe('opencode')
  expect(providerClient.configure).toHaveBeenCalledExactlyOnceWith('openai/test-model', 'opencode')
})

it('connects and removes an operator OpenCode credential without re-displaying the key', async () => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'platform_operator', actorId: 'operator', platformOperationsAllowed: true, statebenchInspectionAllowed: false } } })
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
  const operatorSession = { state: 'connected' as const, endpoint: '', actor: { role: 'platform_operator' as const, actorId: 'operator', platformOperationsAllowed: true, statebenchInspectionAllowed: false } }
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

  it('does not render the adopt controls for Codex and refuses them without provider permission', async () => {
    vi.mocked(providerClient.getStatus).mockResolvedValue({ ...base, providerId: 'codex' })
    const codex = render(<ProviderSettings />)
    await screen.findByText('Selected provider')
    expect(screen.queryByRole('button', { name: 'Adopt existing OpenCode sign-in' })).toBeNull()
    codex.unmount()

    useSessionStore.setState({ serviceStatus: { ...operatorSession, actor: { ...operatorSession.actor, providerActionsAllowed: false } } })
    vi.mocked(providerClient.getStatus).mockResolvedValue(base)
    const denied = render(<ProviderSettings />)
    const button = await screen.findByRole('button', { name: 'Adopt existing OpenCode sign-in' }) as HTMLButtonElement
    expect(button.disabled).toBe(true)
    expect(providerClient.adoptSignIn).not.toHaveBeenCalled()
    denied.unmount()
  })
})
