/**
 * CatalogPage — the reviewed package surface against the real MockClient:
 * seeded packages render with review classification, the updates section is
 * quiet and factual, search drives the honest empty state, installation always
 * goes through the plain-language review step before
 * client.catalog.createInstance runs and the UI navigates to the new instance,
 * and a catalog load failure surfaces an honest error with Retry.
 *
 * Note: @testing-library/jest-dom is not installed — assertions use plain
 * matchers on textContent / query results.
 */
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useParams } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests, useScenarioStore } from '@/client'

import CatalogPage from '../CatalogPage'

function InstanceProbe() {
  const { instanceId } = useParams()
  return <div data-testid="instance-overview">{instanceId}</div>
}

function renderCatalog(initial = '/catalog') {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/catalog" element={<CatalogPage />} />
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
  useScenarioStore.getState().setActive(null)
  resetClientForTests()
})

describe('CatalogPage', () => {
  it('renders the seeded packages with review classification and updates', async () => {
    renderCatalog()
    const list = await screen.findByTestId('package-list')
    expect(within(list).getByText('ProjectState')).toBeTruthy()
    expect(within(list).getByText('StudyState')).toBeTruthy()
    expect(within(list).getByText('LedgerState')).toBeTruthy()
    // Review classification: reviewed vs community — unreviewed.
    expect(within(list).getAllByText('Reviewed').length).toBeGreaterThan(0)
    expect(within(list).getByText('Community — unreviewed')).toBeTruthy()
    // Updates section (quiet, reviewed) for the checklist package.
    expect(screen.getByText('Updates available')).toBeTruthy()
    expect(screen.getByText(/v1\.0\.0 → v1\.1\.0/)).toBeTruthy()
    expect(
      screen.getByText(/Applying an update is not yet exposed/),
    ).toBeTruthy()
  })

  it('search with no matches shows the honest empty state and clears', async () => {
    const user = userEvent.setup()
    renderCatalog()
    const search = await screen.findByRole('searchbox', { name: /search packages/i })
    await user.type(search, 'zzz-no-such-package')

    expect(await screen.findByText('No packages match')).toBeTruthy()
    expect(screen.queryByTestId('package-list')).toBeNull()

    await user.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(await screen.findByTestId('package-list')).toBeTruthy()
  })

  it('install goes through the review step, creates the instance, and navigates', async () => {
    const user = userEvent.setup()
    renderCatalog()

    // NotesState is not installed in the seed → primary action is "Install".
    const install = await screen.findByTestId('install-notes-state')
    await user.click(install)

    // The review step explains, in plain language, before anything happens.
    const review = await screen.findByTestId('install-review')
    expect(review.textContent).toContain('What it can do')
    expect(review.textContent).toContain('Reads and writes notes inside its own folder only.')
    expect(review.textContent).toContain('No terminal access.')
    expect(review.textContent).toContain(
      'Installing this package requires your confirmation. It does not change any existing application.',
    )

    const nameInput = within(review).getByTestId('instance-name-input')
    await user.clear(nameInput)
    await user.type(nameInput, 'Field notes')
    await user.click(within(review).getByTestId('confirm-install'))

    const success = await screen.findByTestId('install-success', undefined, { timeout: 4000 })
    expect(success.textContent).toContain('Field notes is installed')
    const receiptLink = within(success).getByTestId('view-install-receipt')
    expect(receiptLink.getAttribute('href')).toMatch(
      /^\/app\/ins_\d+\/receipts\/rcpt_\d+\?digest=[0-9a-f]{64}$/,
    )

    await user.click(within(success).getByTestId('open-instance'))
    const overview = await screen.findByTestId('instance-overview')
    expect(overview.textContent).toMatch(/^ins_\d+$/)
  })

  it('does not offer a blind retry when an installation result is uncertain', async () => {
    const user = userEvent.setup()
    const create = vi
      .spyOn(getClient().catalog, 'createInstance')
      .mockRejectedValue(new Error('The completed mutation response had a mismatched receipt digest.'))
    renderCatalog()

    await user.click(await screen.findByTestId('install-notes-state'))
    const review = await screen.findByTestId('install-review')
    await user.click(within(review).getByTestId('confirm-install'))

    const error = await screen.findByTestId('install-error')
    expect(error.textContent).toContain('Installation result could not be confirmed')
    expect(error.textContent).toContain('Do not retry this mutation')
    expect(within(error).queryByRole('button', { name: /retry/i })).toBeNull()
    expect(
      (within(screen.getByTestId('install-review')).getByTestId(
        'confirm-install',
      ) as HTMLButtonElement).disabled,
    ).toBe(true)
    expect(create).toHaveBeenCalledTimes(1)
  })

  it('does not claim success from a mutation digest when the durable reread disagrees', async () => {
    const user = userEvent.setup()
    const client = getClient()
    const originalCreate = client.catalog.createInstance
    vi.spyOn(client.catalog, 'createInstance').mockImplementation(async (packageId, input) => {
      const created = await originalCreate(packageId, input)
      return {
        ...created,
        receipt: { ...created.receipt, digest: { ...created.receipt.digest, value: 'f'.repeat(64) } },
      }
    })
    renderCatalog()

    await user.click(await screen.findByTestId('install-notes-state'))
    const review = await screen.findByTestId('install-review')
    await user.click(within(review).getByTestId('confirm-install'))

    const error = await screen.findByTestId('install-error')
    expect(error.textContent).toContain('durable installation receipt did not match')
    expect(screen.queryByTestId('install-success')).toBeNull()
  })

  it('catalog load failure is an honest error state with retry', async () => {
    useScenarioStore.getState().setActive('request_failure')
    renderCatalog()
    expect(await screen.findByText("The package catalog couldn't be loaded")).toBeTruthy()
    expect(screen.getByRole('button', { name: /retry/i })).toBeTruthy()
  })
})
