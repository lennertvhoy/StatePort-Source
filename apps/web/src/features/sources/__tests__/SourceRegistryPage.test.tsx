/**
 * Source registry surface: normal users receive only bounded release status;
 * a backend-identified platform operator may inspect redacted exact evidence
 * and explicitly verify the immutable development candidate.
 */
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests } from '@/client'

import SourceRegistryPage from '../SourceRegistryPage'

function renderSources(initial = '/sources') {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/sources" element={<SourceRegistryPage />} />
        <Route path="/sources/:sourceId" element={<SourceRegistryPage />} />
        <Route path="/catalog" element={<div data-testid="catalog">Catalog</div>} />
        <Route path="/statebench" element={<div data-testid="statebench">StateBench</div>} />
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

describe('SourceRegistryPage', () => {
  it('shows only bounded public status to a normal user', async () => {
    const client = getClient()
    const detail = vi.spyOn(client.sources, 'getOperatorDetail')
    renderSources('/sources/stateport.source.studystate')

    expect(await screen.findByText('StudyState')).toBeTruthy()
    expect(screen.getByText('Awaiting verified release')).toBeTruthy()
    expect(screen.getByText(/Operator access required/)).toBeTruthy()
    expect(screen.queryByText(/github\.com\/example\/studystate-template/)).toBeNull()
    expect(screen.queryByTestId('development-candidate')).toBeNull()
    expect(screen.queryByTestId('open-platform-statebench')).toBeNull()
    expect(detail).not.toHaveBeenCalled()
  })

  it('lets a platform operator inspect exact redacted evidence and verify the bound candidate', async () => {
    const user = userEvent.setup()
    const client = getClient()
    vi.spyOn(client.session, 'getLocalServiceStatus').mockResolvedValue({
      state: 'connected',
      endpoint: '/v1/status',
      actor: {
        role: 'platform_operator',
        actorId: 'platform-operator',
        platformOperationsAllowed: true,
        statebenchInspectionAllowed: true,
      },
    })
    const verify = vi.spyOn(client.sources, 'verifyDevelopmentCandidate')
    renderSources()

    expect(await screen.findByTestId('open-platform-statebench')).toBeTruthy()
    await user.click(await screen.findByTestId('inspect-source-stateport.source.studystate'))
    const detail = await screen.findByTestId('source-operator-detail')
    expect(detail.textContent).toContain('Development candidate')
    expect(detail.textContent).toContain('Not a release')
    expect(detail.textContent).toContain('Production install')
    expect(detail.textContent).toContain('Not allowed')
    expect(detail.textContent).toContain('https://github.com/example/studystate-template.git')
    expect(detail.textContent).not.toContain('/home/')

    await user.click(screen.getByTestId('verify-development-candidate'))
    expect(await screen.findByTestId('confirm-dialog')).toBeTruthy()
    await user.click(screen.getByTestId('confirm-action'))

    expect(await screen.findByText('Development verification recorded')).toBeTruthy()
    expect(screen.getByText(/Production install remains unavailable/)).toBeTruthy()
    expect(screen.getByText(/No — declarations were matched only/)).toBeTruthy()
    expect(verify).toHaveBeenCalledWith(
      expect.objectContaining({
        sourceId: 'stateport.source.studystate',
        sourceClass: 'development_candidate',
        expectedCommit: '7b8a6449361578264952f985d70655233e870b4e',
      }),
    )
  })

  it('does not disclose the StateBench destination when an operator permission bit is absent', async () => {
    const client = getClient()
    vi.spyOn(client.session, 'getLocalServiceStatus').mockResolvedValue({
      state: 'connected',
      endpoint: '/v1/status',
      actor: {
        role: 'platform_operator',
        actorId: 'platform-operator',
        platformOperationsAllowed: true,
        statebenchInspectionAllowed: false,
      },
    })

    renderSources()

    expect(await screen.findByText('StudyState')).toBeTruthy()
    expect(screen.queryByTestId('open-platform-statebench')).toBeNull()
  })
})
