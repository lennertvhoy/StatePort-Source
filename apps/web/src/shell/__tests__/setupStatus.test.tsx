import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests } from '@/client'
import { resetMockState } from '@/client/mock/adapter'
import { providerClient, type ProviderStatus } from '@/client/providerClient'
import { useSessionStore } from '@/state'

import PlatformPage from '../PlatformPage'
import { SetupStatus } from '../SetupStatus'
import { modelStateFrom } from '../setupStatusModel'

function providerStatus(overrides: Partial<ProviderStatus> = {}): ProviderStatus {
  return {
    configured: false,
    executableInstalled: true,
    connected: false,
    model: null,
    authenticationStatus: 'unverified',
    requestStatus: 'unverified',
    telemetryStatus: 'unavailable',
    detail: '',
    ...overrides,
  }
}

beforeEach(() => {
  resetClientForTests()
  resetMockState()
  vi.spyOn(providerClient, 'getStatus').mockResolvedValue(providerStatus())
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: 'http://localhost' } })
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.useRealTimers()
  resetClientForTests()
})

function line(name: string) {
  return within(screen.getByText(name).closest('div')!)
}

it('says plainly that the service is connected, the model is not set up and there are no applications', async () => {
  vi.spyOn(getClient().applications, 'list').mockResolvedValue([])
  render(<MemoryRouter><SetupStatus /></MemoryRouter>)
  await waitFor(() => expect(line('Applications').getByText('None yet')).toBeTruthy())
  expect(line('StatePort service').getByText('Connected')).toBeTruthy()
  expect(line('AI model').getByText('Not set up yet')).toBeTruthy()
  expect(line('AI model').getByRole('link', { name: 'Set up a model' }).getAttribute('href')).toBe('/settings/models')
  // No internal jargon about executables, authentication phases or workers.
  const text = screen.getByTestId('setup-status').textContent ?? ''
  expect(text).not.toMatch(/executable|authentication|configuration:|worker|request:/i)
})

it('shows the saved model as ready, and marks it not checked until a check has passed', async () => {
  vi.spyOn(providerClient, 'getStatus').mockResolvedValue(
    providerStatus({ configured: true, connected: true, model: 'opencode/test-model' }),
  )
  vi.spyOn(getClient().applications, 'list').mockResolvedValue([])
  render(<MemoryRouter><SetupStatus /></MemoryRouter>)
  await waitFor(() => expect(line('AI model').getByText('Ready with opencode/test-model (not checked yet)')).toBeTruthy())
  cleanup()
  vi.spyOn(providerClient, 'getStatus').mockResolvedValue(
    providerStatus({ configured: true, connected: true, model: 'opencode/test-model', requestStatus: 'succeeded' }),
  )
  render(<MemoryRouter><SetupStatus /></MemoryRouter>)
  await waitFor(() => expect(line('AI model').getByText('Ready with opencode/test-model')).toBeTruthy())
})

it('reduces every provider observation to ready, not set up, or unavailable with a reason', () => {
  expect(modelStateFrom(providerStatus())).toEqual({ kind: 'not_set_up' })
  expect(modelStateFrom(providerStatus({ configured: true, model: 'm', connected: false }))).toMatchObject({ kind: 'unavailable' })
  expect(modelStateFrom(providerStatus({ configured: true, model: 'm', connected: true, executableStatus: 'missing', executableInstalled: false })))
    .toMatchObject({ kind: 'unavailable', reason: expect.stringContaining('not installed') })
  expect(modelStateFrom(providerStatus({ configured: true, model: 'm', connected: true, requestStatus: 'failed', detail: 'quota reached' })))
    .toEqual({ kind: 'unavailable', reason: 'quota reached' })
  expect(modelStateFrom(providerStatus({ configured: true, model: 'm', connected: true, authenticationStatus: 'unauthenticated' })))
    .toMatchObject({ kind: 'unavailable' })
})

it('reports an unreachable service and an unreadable model status instead of guessing', async () => {
  useSessionStore.setState({ serviceStatus: { state: 'offline', endpoint: '' } })
  render(<MemoryRouter><SetupStatus /></MemoryRouter>)
  expect(line('StatePort service').getByText('Unreachable')).toBeTruthy()
  expect(line('AI model').getByText(/Unavailable: the StatePort service is not reachable/)).toBeTruthy()
  expect(line('Applications').getByText('Not available while the service is unreachable')).toBeTruthy()
  cleanup()

  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '' } })
  vi.spyOn(providerClient, 'getStatus').mockRejectedValue(new Error('down'))
  render(<MemoryRouter><SetupStatus /></MemoryRouter>)
  await waitFor(() => expect(line('AI model').getByText(/Unavailable: the model status could not be read/)).toBeTruthy())
})

it('re-reads the model on the shell service-poll revision, not on its own interval', async () => {
  vi.useFakeTimers()
  const getStatus = vi.mocked(providerClient.getStatus)
  render(<MemoryRouter><SetupStatus /></MemoryRouter>)
  await act(async () => { await vi.advanceTimersByTimeAsync(0) })
  expect(getStatus).toHaveBeenCalledTimes(1)
  await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
  expect(getStatus).toHaveBeenCalledTimes(1)
  act(() => {
    useSessionStore.getState().setServiceStatus({ state: 'connected', endpoint: 'http://localhost' })
  })
  await act(async () => { await vi.advanceTimersByTimeAsync(0) })
  expect(getStatus).toHaveBeenCalledTimes(2)
})

it('lists only pages that work for the session on the platform hub', () => {
  useSessionStore.setState({
    serviceStatus: {
      state: 'connected',
      endpoint: '',
      actor: { role: 'local_user', actorId: 'user', platformOperationsAllowed: false, statebenchInspectionAllowed: false },
    },
  })
  render(<MemoryRouter><PlatformPage /></MemoryRouter>)
  const links = within(screen.getByRole('navigation', { name: 'Platform controls' })).getAllByRole('link')
  expect(links.map((link) => link.getAttribute('href'))).toEqual(['/settings/models', '/execution-host', '/settings/advanced'])
  cleanup()

  useSessionStore.setState({
    serviceStatus: {
      state: 'connected',
      endpoint: '',
      actor: { role: 'platform_operator', actorId: 'operator', platformOperationsAllowed: true, statebenchInspectionAllowed: true },
    },
  })
  render(<MemoryRouter><PlatformPage /></MemoryRouter>)
  const operatorLinks = within(screen.getByRole('navigation', { name: 'Platform controls' })).getAllByRole('link')
  expect(operatorLinks.map((link) => link.getAttribute('href'))).toEqual([
    '/settings/models', '/execution-host', '/authority', '/updater', '/settings/advanced',
  ])
  // None of the removed surfaces is linked from the hub.
  for (const removed of ['/sources', '/deployments', '/preview-routes', '/statebench']) {
    expect(operatorLinks.some((link) => link.getAttribute('href') === removed)).toBe(false)
  }
})
