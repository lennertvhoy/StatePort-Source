/**
 * ImportRepositoryDrawer — the governed local-repository import flow:
 * discovery → read-only inspection → exact-identity review → explicit
 * approval → registration → open the new application.
 */
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useParams } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests } from '@/client'

import { ImportRepositoryDrawer } from '../ImportRepositoryDrawer'

function InstanceProbe() {
  const { instanceId } = useParams()
  return <div data-testid="instance-overview">{instanceId}</div>
}

function renderDrawer() {
  return render(
    <MemoryRouter initialEntries={['/catalog']}>
      <Routes>
        <Route path="/catalog" element={<ImportRepositoryDrawer open onOpenChange={() => undefined} />} />
        <Route path="/app/:instanceId" element={<InstanceProbe />} />
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

describe('ImportRepositoryDrawer', () => {
  it('walks discovery, inspection, approval, and registration', async () => {
    const user = userEvent.setup()
    const receiptGet = vi.spyOn(getClient().receipts, 'get')
    renderDrawer()

    // Discovery lists the allowlisted candidates.
    const candidates = await screen.findByTestId('import-candidates')
    expect(candidates.textContent).toContain('photography-portfolio')

    // Inspection is read-only and shows the exact identity.
    await user.click(screen.getByTestId('import-candidate-photography-portfolio'))
    const review = await screen.findByTestId('import-review')
    expect(review.textContent).toContain('main')
    expect(review.textContent).toContain('Clean')

    // Registration stays disabled until the exact-identity approval is given.
    const registerButton = screen.getByTestId('import-register') as HTMLButtonElement
    expect(registerButton.disabled).toBe(true)
    await user.click(screen.getByRole('checkbox', { name: /approve registration/i }))
    expect((screen.getByTestId('import-register') as HTMLButtonElement).disabled).toBe(false)

    await user.click(screen.getByTestId('import-register'))
    const done = await screen.findByTestId('import-done')
    expect(done.textContent).toContain('is registered')
    expect(receiptGet).toHaveBeenCalledWith(expect.stringMatching(/^rcpt_/), expect.stringMatching(/^ins-/))
    expect(screen.getByTestId('import-view-receipt').getAttribute('href')).toMatch(
      /^\/app\/ins-[^/]+\/receipts\/rcpt_\d+(\?digest=[0-9a-f]{64})?$/,
    )

    // Opening the registered application navigates to its route.
    await user.click(screen.getByTestId('import-open-application'))
    const overview = await screen.findByTestId('instance-overview')
    expect(overview.textContent).toMatch(/^ins-/)
  })

  it('preserves an inspection error on the candidate list', async () => {
    const user = userEvent.setup()
    vi.spyOn(getClient().repositoryImport, 'inspect').mockRejectedValue(new Error('service unavailable'))
    renderDrawer()

    await screen.findByTestId('import-candidates')
    await user.click(screen.getByTestId('import-candidate-photography-portfolio'))

    expect(await screen.findByTestId('import-candidates')).toBeTruthy()
    expect(screen.getByText('Inspection failed')).toBeTruthy()
    expect(screen.getByTestId('import-candidate-photography-portfolio')).toBeTruthy()
  })

  it('does not claim a receipt when registration returns no receipt ID', async () => {
    const user = userEvent.setup()
    vi.spyOn(getClient().repositoryImport, 'register').mockResolvedValue({ instanceId: 'ins-no-receipt' })
    renderDrawer()

    await user.click(await screen.findByTestId('import-candidate-photography-portfolio'))
    await screen.findByTestId('import-review')
    await user.click(screen.getByRole('checkbox', { name: /approve registration/i }))
    await user.click(screen.getByTestId('import-register'))

    const uncertain = await screen.findByTestId('import-uncertain')
    expect(uncertain.textContent).not.toContain('is registered')
    expect(uncertain.textContent).toContain('receipt ID')
  })

  it.each([
    ['reports a mutation', true],
    ['does not report whether it mutated', undefined],
  ])('holds registration when inspection %s', async (_label, mutated) => {
    const user = userEvent.setup()
    vi.spyOn(getClient().repositoryImport, 'inspect').mockResolvedValue({
      candidateId: 'cand_photography',
      source: 'projects/photography-portfolio',
      inspectionDigest: 'd'.repeat(64),
      branch: 'main',
      headCommit: 'a'.repeat(40),
      dirty: false,
      findings: [],
      mutated,
    })
    renderDrawer()

    await user.click(await screen.findByTestId('import-candidate-photography-portfolio'))
    const review = await screen.findByTestId('import-review')
    expect(within(review).queryByRole('checkbox')).toBeNull()
    expect((screen.getByTestId('import-register') as HTMLButtonElement).disabled).toBe(true)
    expect(review.textContent).toContain('did not prove that the repository was left unmodified')
  })
})
