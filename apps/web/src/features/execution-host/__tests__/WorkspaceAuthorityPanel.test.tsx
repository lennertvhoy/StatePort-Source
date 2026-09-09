import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { getClient, resetClientForTests } from '@/client'
import type { WorkspaceAuthorityPreparation, WorkspaceAuthorityProjection, WorkspaceAuthoritySource } from '@/client/client'
import WorkspaceAuthorityPanel from '../WorkspaceAuthorityPanel'

const digest = `sha256:${'a'.repeat(64)}`
const expiry = '2099-01-01T00:00:00Z'
const projection: WorkspaceAuthorityProjection = {
  instanceId: 'study-one', applicationId: 'studystate', displayName: 'My Study', catalogIdentityDigest: digest, status: 'available',
  issuer: { issuerContextDigest: digest, profileId: 'stateport.empty-workspace/v1', profileDigest: digest, sourceMode: 'empty', grantExpiresAtLimit: expiry,
    profile: { image: { reference: `registry/workspace@${digest}` }, parameters: { cpuQuotaPercent: 100, diskMaxBytes: 123, networkMode: 'none' }, resources: { memoryMaxBytes: 256, pidsMax: 12 }, timeoutSeconds: 3600, outputByteBound: 64 } },
}
function result(review = projection) {
  return { review, request: { formatVersion: 'stateport.workspace-authority-request/v1' as const, instanceId: review.instanceId, applicationId: review.applicationId, catalogIdentityDigest: review.catalogIdentityDigest, issuerContextDigest: digest, profileDigest: digest, sourceMode: 'empty' as const, createdAt: '2098-01-01T00:00:00Z', expiresAt: '2098-01-01T00:15:00Z', grantExpiresAt: expiry, requestDigest: digest } }
}
const reviewedSource: WorkspaceAuthoritySource = {
  baseRevision: 'b'.repeat(40), commitObject: 'dHJlZSBhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhCmF1dGhvciB0ZXN0Cg==',
  sourceInventory: [{ path: 'application.yaml', mode: '100644', contentDigest: digest }, { path: 'bin/run.sh', mode: '100755', contentDigest: digest }],
  sourceArchive: { formatVersion: 'stateport.deployment-context-archive/v1', archiveDigest: digest, archiveBytes: 2048, contextDigest: digest, fileCount: 2 },
  descriptorDigest: digest,
}
const reviewedProjection: WorkspaceAuthorityProjection = {
  ...projection,
  issuer: { ...projection.issuer!, profileId: 'stateport.reviewed-source-workspace-terminal/v1', sourceMode: 'reviewed-commit', operations: ['createWorkload', 'listWorkloads', 'status', 'logs', 'start', 'stop', 'cancel', 'removeWorkload', 'execWorkload', 'openTerminal', 'resizeTerminal', 'signalTerminal', 'closeTerminal'], profile: { ...projection.issuer!.profile, parameters: { ...projection.issuer!.profile.parameters, shell: ['/bin/sh'] as ['/bin/sh'] } } },
}
function reviewedResult(): WorkspaceAuthorityPreparation {
  return { review: reviewedProjection, request: { formatVersion: 'stateport.workspace-authority-request/v2', instanceId: reviewedProjection.instanceId, applicationId: reviewedProjection.applicationId, catalogIdentityDigest: reviewedProjection.catalogIdentityDigest, issuerContextDigest: digest, profileDigest: digest, sourceMode: 'reviewed-commit', source: reviewedSource, sourceDigest: digest, createdAt: '2098-01-01T00:00:00Z', expiresAt: '2098-01-01T00:15:00Z', grantExpiresAt: expiry, requestDigest: digest } }
}
beforeEach(() => {
  resetClientForTests()
  vi.spyOn(getClient().executionHost, 'workspaceAuthority').mockResolvedValue(projection)
  vi.spyOn(getClient().executionHost, 'prepareWorkspaceAuthority').mockResolvedValue(result())
})
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); resetClientForTests() })
async function review() {
  fireEvent.click(screen.getByRole('button', { name: 'Review workspace authority' }))
  await screen.findByText(/Source: empty workspace/)
  fireEvent.change(screen.getByLabelText('Authority expires at (UTC)'), { target: { value: expiry.slice(0, -1) } })
}
it('reviews exact empty profile and downloads only a prepared request with explicit OS approval', async () => {
  const created = vi.spyOn(getClient().executionHost, 'createDefaultWorkload')
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  expect(screen.getByText(/quota enforcement is unsupported/)).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  const download = await screen.findByRole('link', { name: 'Download authority request' })
  expect(JSON.parse(decodeURIComponent(download.getAttribute('href')!.split(',')[1]))).toEqual(result().request)
  expect(getClient().executionHost.prepareWorkspaceAuthority).toHaveBeenCalledExactlyOnceWith('study-one', { profileDigest: digest, sourceMode: 'empty', grantExpiresAt: expiry })
  expect(screen.queryByText(/Reviewed source inventory/)).toBeNull()
  expect(screen.getByText(/sudo \/usr\/local\/libexec\/stateport-execution-host-provision/).textContent).toContain(`--request-digest ${digest} < downloaded-request.json`)
  expect(created).not.toHaveBeenCalled()
  expect(screen.getByText(/Prepared only; authority has not been issued/)).toBeTruthy()
})
it('prepares and displays the reviewed committed source facts before explicit OS approval', async () => {
  vi.spyOn(getClient().executionHost, 'workspaceAuthority').mockResolvedValue(reviewedProjection)
  vi.spyOn(getClient().executionHost, 'prepareWorkspaceAuthority').mockResolvedValue(reviewedResult())
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  fireEvent.click(screen.getByRole('button', { name: 'Review workspace authority' }))
  await screen.findByText(/server will derive the reviewed committed-file witness/)
  fireEvent.change(screen.getByLabelText('Authority expires at (UTC)'), { target: { value: expiry.slice(0, -1) } })
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await screen.findByRole('link', { name: 'Download authority request' })
  expect(getClient().executionHost.prepareWorkspaceAuthority).toHaveBeenCalledExactlyOnceWith('study-one', { profileDigest: digest, sourceMode: 'reviewed-commit', grantExpiresAt: expiry })
  const preparedSource = screen.getByRole('region', { name: 'Prepared reviewed source' })
  expect(preparedSource.textContent).toContain('Explicit OS operator approval is still required')
  fireEvent.click(screen.getByText('Reviewed source inventory (2 committed files)'))
  expect(preparedSource.textContent).toContain(`bin/run.sh · mode 100755 · ${digest}`)
  expect(preparedSource.textContent).toContain(`context ${digest} · descriptor ${digest}`)
  expect(screen.queryByText('Source: empty workspace. Application source files are not copied by this profile.')).toBeNull()
})
it('does not publish delayed old application review after navigation', async () => {
  let resolve!: (value: WorkspaceAuthorityProjection) => void
  vi.spyOn(getClient().executionHost, 'workspaceAuthority').mockImplementationOnce(() => new Promise(done => { resolve = done }))
  const page = render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  fireEvent.click(screen.getByRole('button', { name: 'Review workspace authority' }))
  page.rerender(<WorkspaceAuthorityPanel instanceId="other-one" applicationId="projectstate" onRefresh={vi.fn()} />)
  await act(async () => resolve(projection))
  expect(screen.queryByText(/My Study/)).toBeNull()
  expect(screen.queryByRole('button', { name: 'Prepare authority request' })).toBeNull()
})
it('refuses catalog replacement during preparation and exposes no download', async () => {
  vi.spyOn(getClient().executionHost, 'prepareWorkspaceAuthority').mockResolvedValue(result({ ...projection, catalogIdentityDigest: `sha256:${'b'.repeat(64)}` }))
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('reviewed identity'))
  expect(screen.queryByRole('link')).toBeNull()
})
it('invalidates prepared download on refresh and renders recorded issuance separately', async () => {
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await screen.findByRole('link')
  vi.spyOn(getClient().executionHost, 'workspaceAuthority').mockResolvedValue({ ...projection, status: 'issued', issued: { status: 'issued', requestDigest: digest } })
  fireEvent.click(screen.getByRole('button', { name: 'Review workspace authority' }))
  await screen.findByText('Recorded workspace authority receipt')
  expect(screen.queryByRole('link')).toBeNull()
  expect(screen.getByText(/Historical issuance only/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Prepare authority request' })).toBeNull()
})
it('disables download for an expired request', async () => {
  const old = result(); old.request.expiresAt = '2000-01-01T00:00:00Z'
  vi.spyOn(getClient().executionHost, 'prepareWorkspaceAuthority').mockResolvedValue(old)
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('request has expired'))
  expect(screen.queryByRole('link')).toBeNull()
})

it('does not publish a late prepared request after application navigation', async () => {
  let resolve!: (value: ReturnType<typeof result>) => void
  vi.spyOn(getClient().executionHost, 'prepareWorkspaceAuthority').mockImplementationOnce(() => new Promise(done => { resolve = done }))
  const page = render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  page.rerender(<WorkspaceAuthorityPanel instanceId="other-one" applicationId="projectstate" onRefresh={vi.fn()} />)
  await act(async () => resolve(result()))
  expect(screen.queryByRole('link')).toBeNull()
  expect(screen.queryByText(/Prepared only/)).toBeNull()
})

it('has no idle cadence and schedules one expiry timeout only for a prepared request', async () => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2098-01-01T00:00:00Z'))
  const interval = vi.spyOn(window, 'setInterval')
  const page = render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  expect(vi.getTimerCount()).toBe(0)
  await act(async () => vi.advanceTimersByTime(60_000))
  expect(interval).not.toHaveBeenCalled()
  expect(getClient().executionHost.workspaceAuthority).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Review workspace authority' }))
  await act(async () => {})
  expect(vi.getTimerCount()).toBe(0)
  fireEvent.change(screen.getByLabelText('Authority expires at (UTC)'), { target: { value: '2099-01-01T00:00' } })
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await act(async () => {})
  expect(vi.getTimerCount()).toBe(1)
  await act(async () => vi.advanceTimersByTime(14 * 60_000 - 1))
  expect(screen.getByRole('link', { name: 'Download authority request' })).toBeTruthy()
  await act(async () => vi.advanceTimersByTime(1))
  expect(screen.queryByRole('link')).toBeNull()
  expect(screen.getByRole('alert').textContent).toContain('request has expired')
  expect(vi.getTimerCount()).toBe(0)
  expect(interval).not.toHaveBeenCalled()
  page.unmount()
  vi.useRealTimers()
})

it('clears a pending expiry timeout on review refresh and scope change', async () => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2098-01-01T00:00:00Z'))
  const page = render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  async function prepared() {
    fireEvent.click(screen.getByRole('button', { name: 'Review workspace authority' }))
    await act(async () => {})
    fireEvent.change(screen.getByLabelText('Authority expires at (UTC)'), { target: { value: '2099-01-01T00:00' } })
    fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
    await act(async () => {})
    expect(vi.getTimerCount()).toBe(1)
  }
  await prepared()
  fireEvent.click(screen.getByRole('button', { name: 'Review workspace authority' }))
  await act(async () => {})
  expect(vi.getTimerCount()).toBe(0)
  await prepared()
  page.rerender(<WorkspaceAuthorityPanel instanceId="other-one" applicationId="projectstate" onRefresh={vi.fn()} />)
  expect(vi.getTimerCount()).toBe(0)
  page.unmount()
  vi.useRealTimers()
})

it('uses an explicit native UTC selection, canonicalizes seconds and preserves the server maximum', async () => {
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  const field = screen.getByLabelText('Authority expires at (UTC)') as HTMLInputElement
  expect(field.type).toBe('datetime-local')
  expect(field.max).toBe('2099-01-01T00:00:00')
  fireEvent.change(field, { target: { value: '2100-01-01T00:00' } })
  expect(screen.getByRole('button', { name: 'Prepare authority request' })).toHaveProperty('disabled', true)
  fireEvent.change(field, { target: { value: '2099-01-01T00:00' } })
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await screen.findByRole('link')
  expect(getClient().executionHost.prepareWorkspaceAuthority).toHaveBeenCalledWith('study-one', { profileDigest: digest, sourceMode: 'empty', grantExpiresAt: '2099-01-01T00:00:00Z' })
})

it('presents binary memory, output and disk limits in readable units', async () => {
  vi.spyOn(getClient().executionHost, 'workspaceAuthority').mockResolvedValue({ ...projection, issuer: { ...projection.issuer!, profile: { ...projection.issuer!.profile, resources: { memoryMaxBytes: 268435456, pidsMax: 12 }, outputByteBound: 65536, parameters: { cpuQuotaPercent: 100, diskMaxBytes: 1073741824, networkMode: 'none' } } } })
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  expect(screen.getByText(/Memory 256 MiB/).textContent).toContain('workload output bound 64 KiB')
  expect(screen.getByText(/Persistent disk request: 1 GiB/)).toBeTruthy()
})

it('labels daemon-verified binding identity without an operator or issuance-time attestation', async () => {
  vi.spyOn(getClient().executionHost, 'workspaceAuthority').mockResolvedValue({ ...projection, status: 'issued', issued: { status: 'daemon-verified-grant', grantId: 'actual-grant', authorityGrantDigest: digest } })
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  fireEvent.click(screen.getByRole('button', { name: 'Review workspace authority' }))
  await screen.findByText('Daemon-verified workspace binding')
  expect(screen.getByText(/does not attest an operator identity or issuance time/)).toBeTruthy()
  expect(screen.queryByText('Recorded workspace authority receipt')).toBeNull()
})

it('shows the separate shell and terminal-control authority before preparing its exact profile request', async () => {
  const terminal = { ...projection, issuer: { ...projection.issuer!, profileId: 'stateport.empty-workspace-terminal/v1' as const, sourceMode: 'empty' as const, operations: ['createWorkload', 'listWorkloads', 'status', 'logs', 'start', 'stop', 'cancel', 'removeWorkload', 'execWorkload', 'openTerminal', 'resizeTerminal', 'signalTerminal', 'closeTerminal'], profile: { ...projection.issuer!.profile, parameters: { ...projection.issuer!.profile.parameters, shell: ['/bin/sh'] as ['/bin/sh'] } } } }
  vi.spyOn(getClient().executionHost, 'workspaceAuthority').mockResolvedValue(terminal)
  vi.spyOn(getClient().executionHost, 'prepareWorkspaceAuthority').mockResolvedValue(result(terminal))
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  const controls = screen.getByRole('region', { name: 'Explicit workspace terminal authority' })
  expect(controls.textContent).toContain('interactive /bin/sh PTY')
  expect(controls.textContent).toContain('openTerminal')
  expect(controls.textContent).toContain('resizeTerminal')
  expect(controls.textContent).toContain('SIGINT, SIGQUIT or SIGTSTP')
  expect(controls.textContent).toContain('not a total terminal-session output cap')
  expect(getClient().executionHost.prepareWorkspaceAuthority).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await screen.findByRole('link')
  expect(getClient().executionHost.prepareWorkspaceAuthority).toHaveBeenCalledWith('study-one', { profileDigest: digest, sourceMode: 'empty', grantExpiresAt: expiry })
})

it('does not infer terminal authority from the legacy empty profile', async () => {
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  expect(screen.queryByRole('region', { name: 'Explicit workspace terminal authority' })).toBeNull()
})

it('keeps a still-valid prepared request while checking for operator approval', async () => {
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await screen.findByRole('link', { name: 'Download authority request' })
  fireEvent.click(screen.getByRole('button', { name: 'Check operator approval' }))
  await waitFor(() => expect(getClient().executionHost.workspaceAuthority).toHaveBeenCalledTimes(2))
  expect(screen.getByRole('heading', { name: 'Pending operator approval' })).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Download authority request' })).toBeTruthy()
})

it('clears a prepared request when operator approval observes a changed identity', async () => {
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await screen.findByRole('link', { name: 'Download authority request' })
  vi.spyOn(getClient().executionHost, 'workspaceAuthority').mockResolvedValue({ ...projection, catalogIdentityDigest: `sha256:${'b'.repeat(64)}` })
  fireEvent.click(screen.getByRole('button', { name: 'Check operator approval' }))
  await waitFor(() => expect(screen.queryByRole('link', { name: 'Download authority request' })).toBeNull())
})

it('clears a prepared request when operator approval becomes unavailable', async () => {
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await screen.findByRole('link', { name: 'Download authority request' })
  vi.spyOn(getClient().executionHost, 'workspaceAuthority').mockResolvedValue({ ...projection, status: 'unavailable', issuer: undefined, refusal: { reason: 'authority_unavailable', detail: 'Current authority could not be checked' } })
  fireEvent.click(screen.getByRole('button', { name: 'Check operator approval' }))
  await waitFor(() => expect(screen.queryByRole('link', { name: 'Download authority request' })).toBeNull())
})

it('clears a prepared request after an operator approval check transport failure', async () => {
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await screen.findByRole('link', { name: 'Download authority request' })
  vi.spyOn(getClient().executionHost, 'workspaceAuthority').mockRejectedValue(new Error('offline'))
  fireEvent.click(screen.getByRole('button', { name: 'Check operator approval' }))
  await waitFor(() => expect(screen.queryByRole('link', { name: 'Download authority request' })).toBeNull())
  expect(screen.getByRole('alert').textContent).toContain('no longer downloadable')
})

it('clears an expired prepared request during the operator approval check', async () => {
  const old = result()
  old.request.expiresAt = '2000-01-01T00:00:00Z'
  vi.spyOn(getClient().executionHost, 'prepareWorkspaceAuthority').mockResolvedValue(old)
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await screen.findByText(/request has expired/)
  fireEvent.click(screen.getByRole('button', { name: 'Check operator approval' }))
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Check operator approval' })).toBeNull())
})

it('uses the earlier grant expiry and clears the pending request as it expires', async () => {
  const earlierGrant = result()
  earlierGrant.request.expiresAt = '2099-01-01T00:00:01Z'
  vi.spyOn(getClient().executionHost, 'prepareWorkspaceAuthority').mockResolvedValue(earlierGrant)
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2098-12-31T23:59:58Z'))
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await act(async () => {})
  expect(screen.getByRole('link', { name: 'Download authority request' })).toBeTruthy()
  expect(vi.getTimerCount()).toBe(1)
  await act(async () => vi.advanceTimersByTime(2_001))
  expect(screen.queryByRole('link', { name: 'Download authority request' })).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Check operator approval' }))
  await act(async () => {})
  expect(screen.queryByRole('button', { name: 'Check operator approval' })).toBeNull()
})

it('fails closed when preparation returns an invalid grant expiry', async () => {
  const invalid = result()
  invalid.request.grantExpiresAt = 'not-a-date'
  vi.spyOn(getClient().executionHost, 'prepareWorkspaceAuthority').mockResolvedValue(invalid)
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" onRefresh={vi.fn()} />)
  await review()
  fireEvent.click(screen.getByRole('button', { name: 'Prepare authority request' }))
  await screen.findByRole('alert')
  expect(screen.queryByRole('link', { name: 'Download authority request' })).toBeNull()
})

it('distinguishes an existing seeded binding from the empty request profile', async () => {
  render(<WorkspaceAuthorityPanel instanceId="study-one" applicationId="studystate" sourceReview={{ reviewDigest: digest, baseRevision: 'b'.repeat(40), archiveDigest: digest, archiveBytes: 1024, fileCount: 2, paths: ['application.yaml', 'state.yaml'] }} onRefresh={vi.fn()} />)
  fireEvent.click(screen.getByRole('button', { name: 'Review workspace authority' }))
  await screen.findByRole('region', { name: 'Existing seeded workspace binding' })
  expect(screen.getByText(/separate from the empty authority request/)).toBeTruthy()
  expect(screen.getByText(/Source: empty workspace/)).toBeTruthy()
})
