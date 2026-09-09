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
import { applicationDestinationAvailable } from '@/features/application-experience/registry'

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
  vi.restoreAllMocks()
  resetClientForTests()
})

describe('ImportRepositoryDrawer', () => {
  it('keeps public acquisition refusal separate from explicit import approval', async () => {
    const user = userEvent.setup()
    const client = getClient()
    vi.spyOn(client.repositoryImport, 'listLocalCandidates').mockResolvedValue([])
    const inspect = vi.spyOn(client.repositoryImport, 'inspectPublic').mockRejectedValue(new Error('Exact public commit unavailable'))
    const install = vi.spyOn(client.repositoryImport, 'installTemplate')
    const register = vi.spyOn(client.repositoryImport, 'register')
    renderDrawer()
    await user.type(await screen.findByLabelText('Public HTTPS repository'), 'https://example.com/template')
    await user.type(screen.getByLabelText('Exact Git commit'), 'c'.repeat(40))
    await user.click(screen.getByRole('button', { name: 'Fetch and inspect' }))
    expect(await screen.findByText('Exact public commit unavailable')).toBeTruthy()
    expect(inspect).toHaveBeenCalledWith('https://example.com/template', 'c'.repeat(40))
    expect(install).not.toHaveBeenCalled()
    expect(register).not.toHaveBeenCalled()
    expect((screen.getByLabelText('Exact Git commit') as HTMLInputElement).value).toBe('c'.repeat(40))
  })

  it.each(['local', 'public'])('creates a detected %s ProjectState template as an isolated managed application', async (sourceKind) => {
    const user = userEvent.setup()
    const client = getClient()
    const existing = (await client.applications.list()).find((instance) =>
      applicationDestinationAvailable(instance, 'receipts'),
    )
    expect(existing).toBeTruthy()
    const existingReceipt = (await client.receipts.list({ instanceId: existing!.id }))[0]
    expect(existingReceipt).toBeTruthy()
    const instanceId = 'template-projectstate-e2e'
    const receiptId = 'template-import-projectstate-e2e'
    vi.spyOn(client.repositoryImport, sourceKind === 'public' ? 'inspectPublic' : 'inspect').mockResolvedValue({
      candidateId: 'cand_photography',
      source: 'ProjectState_Template',
      inspectionDigest: `sha256:${'d'.repeat(64)}`,
      branch: 'main',
      headCommit: 'c'.repeat(40),
      dirty: true,
      findings: [],
      mutated: false,
      template: {
        formatVersion: 'stateport.template-adapter-match/v1',
        adapterId: 'projectstate-v6',
        applicationId: 'stateport.template.projectstate',
        displayName: 'ProjectState',
        description: 'A StatePort-managed ProjectState workspace.',
        templateKind: 'projectstate_v6',
        declaredTemplateId: 'projectstate',
        declaredVersion: 'projectstate-template-v6',
        markerFiles: ['PROJECT.md', 'STATE.yaml'],
        requestedCapabilities: ['conversation', 'receipts'],
        trustedActionIds: ['stateport.template.projectstate.inspect/v1'],
        executionTrust: 'stateport_owned_adapter_only',
        repositoryCommandsExecuted: false,
        validation: { status: 'passed', issues: [] },
      },
    })
    const install = vi.spyOn(client.repositoryImport, 'installTemplate').mockResolvedValue({
      instanceId,
      conversationId: 'conv-projectstate-e2e',
      receiptId,
    })
    vi.spyOn(client.applications, 'get').mockResolvedValue({ ...existing!, id: instanceId })
    vi.spyOn(client.receipts, 'get').mockResolvedValue({
      ...existingReceipt!,
      id: receiptId,
      instanceId,
    })
    renderDrawer()

    if (sourceKind === 'public') {
      await user.type(await screen.findByLabelText('Public HTTPS repository'), 'https://example.com/template')
      await user.type(screen.getByLabelText('Exact Git commit'), 'c'.repeat(40))
      await user.click(screen.getByRole('button', { name: 'Fetch and inspect' }))
    } else {
      await user.click(await screen.findByTestId('import-candidate-photography-portfolio'))
    }
    const review = await screen.findByTestId('import-review')
    expect(within(review).getByTestId('template-adapter-match').textContent).toContain('ProjectState')
    expect(within(review).getByTestId('template-adapter-match').textContent).toContain(
      'uncommitted files are excluded',
    )
    expect(screen.getByTestId('import-register').textContent).toBe('Create isolated copy')
    expect(install).not.toHaveBeenCalled()
    await user.click(
      screen.getByRole('checkbox', {
        name: /approve creation of an isolated copy of the exact inspected template/i,
      }),
    )
    await user.click(screen.getByTestId('import-register'))

    const done = await screen.findByTestId('import-done')
    expect(done.textContent).toContain('is ready')
    expect(done.textContent).toContain('isolated StatePort-managed copy')
    expect(install).toHaveBeenCalledWith(
      expect.objectContaining({
        candidateId: 'cand_photography',
        approved: true,
        inspection: expect.objectContaining({
          template: expect.objectContaining({ adapterId: 'projectstate-v6' }),
        }),
      }),
    )
    await user.click(screen.getByTestId('import-open-application'))
    expect((await screen.findByTestId('instance-overview')).textContent).toBe(instanceId)
  })

  it('walks discovery, inspection, approval, and registration', async () => {
    const user = userEvent.setup()
    const client = getClient()
    const detected = await client.repositoryImport.inspect('cand_photography')
    vi.spyOn(client.repositoryImport, 'inspect').mockResolvedValue({
      ...detected,
      template: undefined,
    })
    const receiptGet = vi.spyOn(client.receipts, 'get')
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
    vi.spyOn(getClient().repositoryImport, 'installTemplate').mockResolvedValue({
      instanceId: 'ins-no-receipt',
    })
    renderDrawer()

    await user.click(await screen.findByTestId('import-candidate-photography-portfolio'))
    await screen.findByTestId('import-review')
    await user.click(screen.getByRole('checkbox', { name: /approve creation of an isolated copy/i }))
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
