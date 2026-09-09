/// <reference types="node" />
import { execFileSync, spawnSync } from 'node:child_process'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ProviderSettings } from '../ProviderSettings'
import { providerClient, type ProviderStatus } from '@/client/providerClient'
import { useSessionStore } from '@/state'
import { ClientError } from '@/client/types'
vi.mock('@/client/providerClient', () => ({ providerClient: { getStatus: vi.fn(), configure: vi.fn(), verify: vi.fn(), disconnect: vi.fn() } }))
const status: ProviderStatus = { configured: false, executableInstalled: false, connected: false, model: null, authenticationStatus: 'unavailable', requestStatus: 'unverified', telemetryStatus: 'unavailable', detail: 'Codex is missing in this runtime.' }
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

it('saves OpenCode as the actual selection, shows refusal, and retains it after reopening', async () => {
  vi.resetAllMocks()
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'platform_operator', actorId: 'operator', platformOperationsAllowed: true, statebenchInspectionAllowed: false } } })
  const selected: ProviderStatus = {
    ...status, providerId: 'opencode', configured: true, connected: false, model: 'opencode/test',
    executableInstalled: true, executableStatus: 'installed', authenticationStatus: 'unavailable',
    executionRefusal: 'sandboxed_validation_not_implemented',
    detail: 'OpenCode selection is saved; isolated post-agent validation is not implemented. No Codex fallback is enabled.',
  }
  vi.mocked(providerClient.getStatus).mockResolvedValueOnce(status).mockResolvedValue({ ...selected, executableStatus: 'unverified' })
  vi.mocked(providerClient.configure).mockResolvedValue(selected)
  vi.mocked(providerClient.verify).mockResolvedValue({ ...selected, requestStatus: 'failed' })
  const user = userEvent.setup()
  const view = render(<ProviderSettings />)
  await screen.findByRole('combobox', { name: 'Coding provider' })
  await user.selectOptions(screen.getByRole('combobox'), 'opencode')
  await user.type(screen.getByRole('textbox', { name: 'OpenCode model identifier' }), 'opencode/test')
  await user.click(screen.getByRole('button', { name: 'Save provider selection' }))
  expect(providerClient.configure).toHaveBeenCalledExactlyOnceWith('opencode/test', 'opencode')
  expect(await screen.findByText(selected.detail)).not.toBeNull()
  expect(screen.queryByRole('button', { name: 'Show installed login command' })).toBeNull()
  expect(screen.getByText('Disconnected')).not.toBeNull()
  await user.click(screen.getByRole('button', { name: 'Check selected adapter' }))
  expect(providerClient.verify).toHaveBeenCalledTimes(1)
  expect(await screen.findByText('failed')).not.toBeNull()
  view.unmount()
  render(<ProviderSettings />)
  await waitFor(() => expect((screen.getByRole('combobox') as HTMLSelectElement).value).toBe('opencode'))
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
  await user.selectOptions(screen.getByRole('combobox'), 'opencode')
  await user.type(screen.getByRole('textbox', { name: 'OpenCode model identifier' }), 'openai/test-model')
  if (beforeSave) {
    await act(async () => resolveInitial(status))
    expect((screen.getByRole('textbox', { name: 'OpenCode model identifier' }) as HTMLInputElement).value).toBe('openai/test-model')
    vi.mocked(providerClient.getStatus).mockResolvedValue(status)
    await user.click(screen.getByRole('button', { name: 'Refresh status' }))
    expect((screen.getByRole('combobox') as HTMLSelectElement).value).toBe('opencode')
    expect((screen.getByRole('textbox') as HTMLInputElement).value).toBe('openai/test-model')
  }
  await user.click(screen.getByRole('button', { name: 'Save provider selection' }))
  await screen.findByText('Selected OpenCode result')
  if (!beforeSave) await act(async () => resolveInitial(status))
  expect(screen.getByText('Selected OpenCode result')).toBeTruthy()
  expect((screen.getByRole('combobox') as HTMLSelectElement).value).toBe('opencode')
  expect(providerClient.configure).toHaveBeenCalledExactlyOnceWith('openai/test-model', 'opencode')
})
