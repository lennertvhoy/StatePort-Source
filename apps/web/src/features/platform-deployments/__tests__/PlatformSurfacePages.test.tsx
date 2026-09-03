/**
 * Honesty tests for the platform surface pages: when the connected adapter
 * reports no durable host state (the mock adapter for these operator
 * surfaces), the pages must render their honest unavailable state and never
 * fabricate operator data or fake a working control.
 */
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests } from '@/client'

import PlatformDeploymentsPage from '../PlatformDeploymentsPage'
import AuthorityPage from '../../authority/AuthorityPage'
import UpdaterPage from '../../updater/UpdaterPage'
import PreviewRoutesPage from '../../preview-routes/PreviewRoutesPage'

function renderAt(path: string, element: React.ReactElement) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path={path} element={element} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  resetClientForTests()
})

afterEach(() => {
  cleanup()
  resetClientForTests()
})

describe('PlatformDeploymentsPage (honest unavailable state)', () => {
  it('renders the page root and the honest unavailable notice (no fake data)', async () => {
    renderAt('/deployments', <PlatformDeploymentsPage />)
    expect(await screen.findByTestId('platform-deployments-page')).toBeTruthy()
    // The mock adapter reports no durable state; the surface must say so
    // honestly rather than rendering a fabricated deployment table.
    expect(await screen.findByText(/No durable deployment state on this host/i)).toBeTruthy()
    expect(screen.queryByTestId('platform-deployments-table')).toBeNull()
  })

  it('loads and exposes exact durable receipt identities in the detail drawer', async () => {
    const deployment = {
      deploymentId: 'deployment-receipts',
      lifecycleState: 'healthy',
      driftStatus: 'in_sync',
      desiredRevision: 'sha256:' + '1'.repeat(64),
      approvedPlanDigest: 'sha256:' + '1'.repeat(64),
      acceptedRevision: 'sha256:' + '1'.repeat(64),
      observedRevision: 'sha256:' + '1'.repeat(64),
      rollback: null,
      retainedDataState: 'retained',
      currentOperation: null,
      serviceHealth: { app: 'healthy' },
    }
    const client = getClient()
    vi.spyOn(client.platformDeployments, 'list').mockResolvedValue({
      formatVersion: 'stateport.deployment-index/v1',
      deployments: [deployment],
    })
    vi.spyOn(client.platformDeployments, 'get').mockResolvedValue({
      state: {
        ...deployment,
        receipts: ['receipt_deployment_000001', 'receipt_deployment_000002'],
      },
    })

    renderAt('/deployments', <PlatformDeploymentsPage />)
    fireEvent.click(await screen.findByTestId('inspect-deployment-deployment-receipts'))

    expect(await screen.findByText('receipt_deployment_000001')).toBeTruthy()
    expect(screen.getByText('receipt_deployment_000002')).toBeTruthy()
    expect(screen.getByTestId('platform-deployment-receipts')).toBeTruthy()
  })
})

describe('AuthorityPage (honest unavailable state)', () => {
  it('renders the page root and the honest unavailable notice', async () => {
    renderAt('/authority', <AuthorityPage />)
    expect(await screen.findByTestId('authority-page')).toBeTruthy()
    expect(await screen.findByText(/Authority store unavailable on this host/i)).toBeTruthy()
    expect(screen.queryByTestId('authority-grants-table')).toBeNull()
  })
})

describe('UpdaterPage (honest unavailable state)', () => {
  it('renders the page root and the honest unavailable notice', async () => {
    renderAt('/updater', <UpdaterPage />)
    expect(await screen.findByTestId('updater-page')).toBeTruthy()
    expect(await screen.findByText(/No installed updater state on this host/i)).toBeTruthy()
    expect(screen.queryByTestId('updater-policy-editor')).toBeNull()
  })
})

describe('PreviewRoutesPage (honest error state)', () => {
  it('renders the page root and surfaces the refused read honestly', async () => {
    renderAt('/preview-routes', <PreviewRoutesPage />)
    expect(await screen.findByTestId('preview-routes-page')).toBeTruthy()
    // The mock refuses; the surface must not fabricate a route table.
    expect(screen.queryByTestId('preview-routes-table')).toBeNull()
  })
})
