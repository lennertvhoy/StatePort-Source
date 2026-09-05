import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { getClient, resetClientForTests, resetMockState } from '@/client'
import { providerClient } from '@/client/providerClient'
import { useSessionStore } from '@/state'
import PlatformPage from '../PlatformPage'
import { ReadinessSummary } from '../ReadinessSummary'

beforeEach(() => {
  resetClientForTests()
  resetMockState()
  vi.spyOn(providerClient, 'getStatus').mockResolvedValue({ configured: false, executableInstalled: true, connected: false, model: null, authenticationStatus: 'unverified', requestStatus: 'unverified', telemetryStatus: 'unavailable', detail: '' })
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: 'http://localhost' } })
})
afterEach(() => { cleanup(); vi.restoreAllMocks(); resetClientForTests() })

it('does not infer execution or provider readiness from a connected service', async () => {
  vi.spyOn(getClient().applications, 'list').mockResolvedValue([])
  render(<MemoryRouter><ReadinessSummary /></MemoryRouter>)
  await waitFor(() => expect(screen.getByText('No applications installed')).toBeTruthy())
  expect(screen.getAllByText('Not checked')).toHaveLength(2)
  expect(screen.getByText(/Executable: installed; configuration: not configured; authentication: unverified; request: unverified/)).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Set up or verify provider' }).getAttribute('href')).toBe('/settings/provider')
  expect(screen.getByRole('link', { name: 'Import a template' }).getAttribute('href')).toBe('/catalog')
})

it('separates runtime reachability from disabled worker execution', () => {
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', runtime: { status: 'available', workerExecutionEnabled: false } } })
  render(<MemoryRouter><ReadinessSummary /></MemoryRouter>)
  expect(screen.getByText('Reachable')).toBeTruthy()
  expect(screen.getByText('Disabled')).toBeTruthy()
})

it('does not present cached runtime or inventory as current when offline', async () => {
  useSessionStore.setState({ serviceStatus: { state: 'offline', endpoint: '', runtime: { status: 'available', workerExecutionEnabled: true } } })
  render(<MemoryRouter><ReadinessSummary /></MemoryRouter>)
  expect(screen.getByText('Offline')).toBeTruthy()
  expect(screen.getByText('Inventory unavailable')).toBeTruthy()
  expect(screen.queryByText('Reachable')).toBeNull()
})

it('makes every existing platform surface discoverable without granting operations', () => {
  useSessionStore.setState({ serviceStatus: { state: 'connected', endpoint: '', actor: { role: 'local_user', actorId: 'user', platformOperationsAllowed: false, statebenchInspectionAllowed: false } } })
  render(<MemoryRouter><PlatformPage /></MemoryRouter>)
  expect(screen.getByRole('status').textContent).toContain('does not permit platform operations')
  const controls = within(screen.getByRole('navigation', { name: 'Platform controls' }))
  expect(controls.getAllByRole('link').map((link) => link.getAttribute('href'))).toEqual(['/settings/provider', '/execution-host', '/sources', '/deployments', '/authority', '/updater', '/preview-routes', '/statebench', '/settings/advanced'])
})
