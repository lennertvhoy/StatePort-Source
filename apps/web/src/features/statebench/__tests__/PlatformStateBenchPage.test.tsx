import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  getClient,
  resetClientForTests,
  type LocalServiceStatus,
  type PlatformStateBenchView,
} from '@/client'

import PlatformStateBenchPage from '../PlatformStateBenchPage'

const LOCAL_USER: LocalServiceStatus = {
  state: 'connected',
  endpoint: '/v1/status',
  actor: {
    role: 'local_user',
    actorId: 'local-user',
    platformOperationsAllowed: false,
    statebenchInspectionAllowed: false,
  },
}

const OPERATOR: LocalServiceStatus = {
  state: 'connected',
  endpoint: '/v1/status',
  actor: {
    role: 'platform_operator',
    actorId: 'platform-operator',
    platformOperationsAllowed: true,
    statebenchInspectionAllowed: true,
  },
}

const BUNDLE_DIGEST = `sha256:${'b'.repeat(64)}`
const MATRIX: PlatformStateBenchView = {
  formatVersion: 'stateport.platform-statebench-view/v1',
  rows: [
    {
      formatVersion: 'statebench.run-bundle-row/v1',
      integrityStatus: 'verified',
      authoritative: false,
      producerClaimsTrusted: false,
      bundleDigest: BUNDLE_DIGEST,
      runId: 'operator-matrix-proof',
      applicationId: 'stateport.synthetic-reference',
      engineId: 'synthetic',
      adapterId: 'synthetic-action',
      status: 'completed',
      statePreserved: true,
      capabilityDegradations: [{ id: 'terminal.sandbox', status: 'unsupported' }],
      acceptedRun: true,
      usageAvailable: null,
      latencyMs: 12,
      unauthorizedMutations: 0,
      bundleFileCount: 6,
    },
  ],
  verifiedRowCount: 1,
  rejectedOrUnverifiedCount: 2,
  truncated: false,
  hardOutcomeOnly: true,
  authoritativePerformanceClaim: false,
  calibrationMeaning: 'Harness behavior only; comparative performance is not established.',
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/statebench']}>
      <Routes>
        <Route path="/statebench" element={<PlatformStateBenchPage />} />
        <Route path="/sources" element={<div>Application sources</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  resetClientForTests()
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  resetClientForTests()
})

describe('PlatformStateBenchPage', () => {
  it('shows an honest operator-only state without calling the endpoint for a normal user', async () => {
    const client = getClient()
    vi.spyOn(client.session, 'getLocalServiceStatus').mockResolvedValue(LOCAL_USER)
    const matrix = vi.spyOn(client.platformStateBench, 'getMatrix')

    renderPage()

    expect(await screen.findByText('Operator access required')).toBeTruthy()
    expect(screen.getByText(/endpoint was not requested/)).toBeTruthy()
    expect(screen.queryByTestId('platform-statebench-table')).toBeNull()
    expect(matrix).not.toHaveBeenCalled()
  })

  it('renders verified and rejected counts plus exact row identities for an operator', async () => {
    const user = userEvent.setup()
    const client = getClient()
    vi.spyOn(client.session, 'getLocalServiceStatus').mockResolvedValue(OPERATOR)
    const matrix = vi.spyOn(client.platformStateBench, 'getMatrix').mockResolvedValue(MATRIX)

    renderPage()

    expect(await screen.findByTestId('platform-statebench-table')).toBeTruthy()
    expect(screen.getByTestId('statebench-verified-count').textContent).toBe('1')
    expect(screen.getByTestId('statebench-rejected-count').textContent).toBe('2')
    expect(screen.getByTestId('statebench-authority-claim').textContent).toContain(
      'authoritativePerformanceClaim: false',
    )
    expect(screen.getByText('stateport.synthetic-reference')).toBeTruthy()
    expect(screen.getByText('synthetic-action')).toBeTruthy()
    expect(matrix).toHaveBeenCalledWith(OPERATOR)

    await user.click(screen.getByTestId('inspect-statebench-operator-matrix-proof'))
    const detail = await screen.findByTestId('platform-statebench-detail')
    expect(detail.textContent).toContain(BUNDLE_DIGEST)
    expect(detail.textContent).toContain('operator-matrix-proof')
    expect(detail.textContent).toContain('stateport.synthetic-reference')
    expect(detail.textContent).toContain('synthetic-action')
    expect(detail.textContent).toContain('Canonical state preserved')
    expect(detail.textContent).toContain('Unauthorized mutations')
    expect(detail.textContent).toContain('12 ms')
    await user.click(screen.getByRole('button', { name: 'Capability degradations (1)' }))
    expect(detail.textContent).toContain('terminal.sandbox')
    expect(detail.textContent).not.toContain('/tmp/')
  })
})
