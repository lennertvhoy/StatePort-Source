import { MemoryRouter } from 'react-router-dom'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { act } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { getClient, resetClientForTests } from '@/client'
import ExecutionHostPage from '../ExecutionHostPage'

const workloads = [
  {
    workloadId: 'project-work', kind: 'workspace', state: 'running', imageDigest: 'sha256:project',
    ownership: { grantId: 'grant-project', applicationId: null, runId: null },
    declaredLimits: { memoryMaxBytes: 268435456, pidsMax: 128, timeoutSeconds: 600, outputByteBound: 65536, cpuQuotaPercent: 100, diskMaxBytes: 268435456 },
    resourceEnforcement: { persistentVolumeDiskMaxBytes: { status: 'unsupported', requestedBytes: 268435456, detail: 'portable rootless Podman named volumes do not expose an enforceable per-volume byte quota' } },
  },
  { workloadId: 'study-work', kind: 'job', state: 'created', imageDigest: 'sha256:study' },
]
beforeEach(() => {
  resetClientForTests()
  vi.spyOn(getClient().executionHost, 'status').mockResolvedValue({ status: 'available', grantBound: true, grantId: 'grant-project' })
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: { workloads } })
})
afterEach(() => { cleanup(); vi.restoreAllMocks(); resetClientForTests() })

it('renders every granted workload from the actual daemon object contract', async () => {
  render(<ExecutionHostPage />)
  expect(await screen.findByRole('article', { name: 'Workload project-work' })).toBeTruthy()
  expect(screen.getByRole('article', { name: 'Workload study-work' })).toBeTruthy()
  expect(screen.getByText('Image: sha256:project')).toBeTruthy()
  expect(screen.getByText(/Authority grant:/).textContent).toContain('grant-project')
  expect(screen.getByText(/Declared limits:/).textContent).toContain('memory 256 MiB')
  expect(screen.getByText(/Declared limits:/).textContent).toContain('persistent disk 256 MiB')
  expect(screen.getByText(/Persistent disk enforcement:/).textContent).toContain('unsupported')
  expect(screen.queryByRole('button', { name: 'Run verification' })).toBeNull()
})

it('rejects malformed ownership and limits instead of rendering invented inventory', async () => {
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({
    accepted: true,
    result: { workloads: [{ workloadId: 'unsafe-work', state: 'running', ownership: { grantId: 7 } }] },
  })
  render(<ExecutionHostPage />)
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('inventory is unavailable'))
  expect(screen.queryByRole('article', { name: 'Workload unsafe-work' })).toBeNull()
})

it('rejects malformed resource enforcement instead of hiding an untrusted limit', async () => {
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({
    accepted: true,
    result: { workloads: [{
      workloadId: 'unsafe-enforcement', state: 'running',
      resourceEnforcement: { persistentVolumeDiskMaxBytes: { status: 'unsupported', requestedBytes: -1, detail: 'bad' } },
    }] },
  })
  render(<ExecutionHostPage />)
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('inventory is unavailable'))
  expect(screen.queryByRole('article', { name: 'Workload unsafe-enforcement' })).toBeNull()
})

it('confirms the exact selected workload before stop and preserves the other workload', async () => {
  const stop = vi.spyOn(getClient().executionHost, 'stopWorkload').mockResolvedValue({ accepted: true, result: { workloadId: 'project-work', state: 'stopped' } })
  render(<ExecutionHostPage />)
  const project = await screen.findByRole('article', { name: 'Workload project-work' })
  fireEvent.click(within(project).getByRole('button', { name: 'Stop' }))
  expect(stop).not.toHaveBeenCalled()
  const dialog = await screen.findByRole('alertdialog')
  expect(within(dialog).getByText('project-work')).toBeTruthy()
  expect(within(dialog).getByText(/workspace volume is preserved/)).toBeTruthy()
  fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm operation' }))
  await waitFor(() => expect(stop).toHaveBeenCalledExactlyOnceWith('project-work'))
  expect(screen.getByRole('article', { name: 'Workload study-work' })).toBeTruthy()
})

it('renders a grant refusal without claiming the selected workload stopped', async () => {
  vi.spyOn(getClient().executionHost, 'stopWorkload').mockResolvedValue({ accepted: false, refusal: { reason: 'grant-revoked', detail: 'operation refused' } })
  render(<ExecutionHostPage />)
  fireEvent.click(within(await screen.findByRole('article', { name: 'Workload project-work' })).getByRole('button', { name: 'Stop' }))
  fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Confirm operation' }))
  expect(await screen.findByText(/project-work: grant-revoked/)).toBeTruthy()
  expect(within(screen.getByRole('article', { name: 'Workload project-work' })).getByText(/Lifecycle: running/)).toBeTruthy()
})

it.each([
  { state: 'removed', allowedOperations: undefined, label: 'removed' },
  { state: 'running', allowedOperations: ['logs'], label: 'revoked operation' },
])('rechecks a pending operation against the current $label row before dispatch', async ({ state, allowedOperations }) => {
  const client = getClient().executionHost
  const stop = vi.spyOn(client, 'stopWorkload')
  const interval = vi.spyOn(window, 'setInterval')
  render(<ExecutionHostPage />)
  const row = await screen.findByRole('article', { name: 'Workload project-work' })
  fireEvent.click(within(row).getByRole('button', { name: 'Stop' }))
  vi.mocked(client.listWorkloads).mockResolvedValueOnce({ accepted: true, result: {
    workloads: [{ ...workloads[0], state, ...(allowedOperations ? { allowedOperations } : {}) }],
  } })
  const poll = interval.mock.calls[0]?.[0] as () => void
  await act(async () => { poll(); await Promise.resolve() })
  await waitFor(() => expect(within(row).getByText(new RegExp(`Lifecycle: ${state}`))).toBeTruthy())
  fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Confirm operation' }))
  expect(await screen.findByText(/changed or is no longer authorized/)).toBeTruthy()
  expect(stop).not.toHaveBeenCalled()
})

it('does not dispatch an old confirmation to a replacement row with the same workload id', async () => {
  const client = getClient().executionHost
  const stop = vi.spyOn(client, 'stopWorkload')
  const interval = vi.spyOn(window, 'setInterval')
  render(<ExecutionHostPage />)
  const row = await screen.findByRole('article', { name: 'Workload project-work' })
  fireEvent.click(within(row).getByRole('button', { name: 'Stop' }))
  vi.mocked(client.listWorkloads).mockResolvedValueOnce({ accepted: true, result: {
    workloads: [{ ...workloads[0], kind: 'job', ownership: { grantId: 'replacement-grant', applicationId: null, runId: null }, allowedOperations: ['stop'] }],
  } })
  const poll = interval.mock.calls[0]?.[0] as () => void
  await act(async () => { poll(); await Promise.resolve() })
  fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Confirm operation' }))
  expect(await screen.findByText(/changed or is no longer authorized/)).toBeTruthy()
  expect(stop).not.toHaveBeenCalled()
})

it('does not dispatch a pending operation after the live inventory is refused', async () => {
  const client = getClient().executionHost
  const stop = vi.spyOn(client, 'stopWorkload')
  const interval = vi.spyOn(window, 'setInterval')
  render(<ExecutionHostPage />)
  const row = await screen.findByRole('article', { name: 'Workload project-work' })
  fireEvent.click(within(row).getByRole('button', { name: 'Stop' }))
  vi.mocked(client.listWorkloads).mockResolvedValueOnce({ accepted: false, refusal: { reason: 'grant-revoked', detail: 'current inventory denied' } })
  const poll = interval.mock.calls[0]?.[0] as () => void
  await act(async () => { poll(); await Promise.resolve() })
  await screen.findByText(/Inventory refused: grant-revoked/)
  fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Confirm operation' }))
  expect(await screen.findByText(/could not be rechecked; no operation was sent/)).toBeTruthy()
  expect(stop).not.toHaveBeenCalled()
})

it('does not treat refused or malformed inventory as empty', async () => {
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: false, refusal: { reason: 'grant-revoked' } })
  const view = render(<ExecutionHostPage />)
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('grant-revoked'))
  expect(screen.queryByRole('button', { name: 'Create development workspace' })).toBeNull()
  view.unmount()
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: [] })
  render(<ExecutionHostPage />)
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('inventory is unavailable'))
  expect(screen.queryByText('No workloads are visible to this grant.')).toBeNull()
})

it('scopes logs to the requested workload and handles transport failures', async () => {
  const logs = vi.spyOn(getClient().executionHost, 'workloadLogs').mockRejectedValue(new Error('transport'))
  render(<ExecutionHostPage />)
  fireEvent.click(within(await screen.findByRole('article', { name: 'Workload study-work' })).getByRole('button', { name: 'Logs' }))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('study-work: logs could not be loaded'))
  expect(logs).toHaveBeenCalledExactlyOnceWith('study-work')
})

it('does not let a late log response repopulate output after inventory authority is refused', async () => {
  const client = getClient().executionHost
  const interval = vi.spyOn(window, 'setInterval')
  let resolveLogs!: (value: { accepted: true; result: { output: string; byteCount: number; outputByteBound: number; truncated: boolean } }) => void
  vi.spyOn(client, 'workloadLogs').mockImplementationOnce(() => new Promise(resolve => { resolveLogs = resolve }))
  render(<ExecutionHostPage />)
  fireEvent.click(within(await screen.findByRole('article', { name: 'Workload study-work' })).getByRole('button', { name: 'Logs' }))
  await waitFor(() => expect(client.workloadLogs).toHaveBeenCalledExactlyOnceWith('study-work'))
  vi.mocked(client.listWorkloads).mockResolvedValueOnce({ accepted: false, refusal: { reason: 'grant-revoked', detail: 'current inventory denied' } })
  const poll = interval.mock.calls[0]?.[0] as () => void
  await act(async () => { poll(); await Promise.resolve(); await Promise.resolve() })
  expect(screen.getByText(/Inventory refused: grant-revoked/)).toBeTruthy()
  await act(async () => resolveLogs({ accepted: true, result: { output: 'private late output', byteCount: 18, outputByteBound: 64, truncated: false } }))
  expect(screen.queryByRole('region', { name: 'Logs for study-work' })).toBeNull()
  expect(screen.queryByText('private late output')).toBeNull()
})

it('ignores a late log response after the page unmounts', async () => {
  const client = getClient().executionHost
  let resolveLogs!: (value: { accepted: true; result: { output: string; byteCount: number; outputByteBound: number; truncated: boolean } }) => void
  vi.spyOn(client, 'workloadLogs').mockImplementationOnce(() => new Promise(resolve => { resolveLogs = resolve }))
  const view = render(<ExecutionHostPage />)
  fireEvent.click(within(await screen.findByRole('article', { name: 'Workload study-work' })).getByRole('button', { name: 'Logs' }))
  await waitFor(() => expect(client.workloadLogs).toHaveBeenCalledExactlyOnceWith('study-work'))
  view.unmount()
  await act(async () => resolveLogs({ accepted: true, result: { output: 'late after unmount', byteCount: 17, outputByteBound: 64, truncated: false } }))
  expect(screen.queryByText('late after unmount')).toBeNull()
})

it('invalidates a log request that starts during a refresh which later fails', async () => {
  const client = getClient().executionHost
  const interval = vi.spyOn(window, 'setInterval')
  let rejectInventory!: (error: Error) => void
  let resolveLogs!: (value: { accepted: true; result: { output: string; byteCount: number; outputByteBound: number; truncated: boolean } }) => void
  vi.spyOn(client, 'workloadLogs').mockImplementationOnce(() => new Promise(resolve => { resolveLogs = resolve }))
  render(<ExecutionHostPage />)
  const row = await screen.findByRole('article', { name: 'Workload study-work' })
  vi.mocked(client.listWorkloads).mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectInventory = reject }))
  fireEvent.click(screen.getByRole('button', { name: 'Refresh workloads' }))
  await waitFor(() => expect(rejectInventory).toBeTypeOf('function'))
  fireEvent.click(within(row).getByRole('button', { name: 'Logs' }))
  await waitFor(() => expect(client.workloadLogs).toHaveBeenCalledExactlyOnceWith('study-work'))
  await act(async () => { rejectInventory(new Error('inventory unavailable')); await Promise.resolve() })
  expect(await screen.findByText(/Workload inventory is unavailable/)).toBeTruthy()
  await act(async () => resolveLogs({ accepted: true, result: { output: 'late after failed refresh', byteCount: 23, outputByteBound: 64, truncated: false } }))
  expect(screen.queryByRole('region', { name: 'Logs for study-work' })).toBeNull()
  expect(screen.queryByText('late after failed refresh')).toBeNull()
  expect(interval).toHaveBeenCalled()
})

it('keeps an in-flight log read through an unchanged successful refresh', async () => {
  const client = getClient().executionHost
  const interval = vi.spyOn(window, 'setInterval')
  let resolveLogs!: (value: Awaited<ReturnType<typeof client.workloadLogs>>) => void
  vi.spyOn(client, 'workloadLogs').mockImplementationOnce(() => new Promise(resolve => { resolveLogs = resolve }))
  render(<ExecutionHostPage />)
  fireEvent.click(within(await screen.findByRole('article', { name: 'Workload study-work' })).getByRole('button', { name: 'Logs' }))
  await waitFor(() => expect(client.workloadLogs).toHaveBeenCalledExactlyOnceWith('study-work'))
  const poll = interval.mock.calls[0]?.[0] as () => void
  await act(async () => { poll(); await Promise.resolve(); await Promise.resolve() })
  await act(async () => resolveLogs({ accepted: true, result: { output: 'slow valid output', byteCount: 17, outputByteBound: 64, truncated: false } }))
  expect(await screen.findByRole('region', { name: 'Logs for study-work' })).toHaveProperty('textContent', expect.stringContaining('slow valid output'))
})

it.each(['operation', 'identity'])('clears retained logs when the refreshed row changes %s', async change => {
  const client = getClient().executionHost
  vi.spyOn(client, 'workloadLogs').mockResolvedValue({ accepted: true, result: { output: 'retained output', byteCount: 15, outputByteBound: 64, truncated: false } })
  const list = vi.mocked(client.listWorkloads)
  render(<ExecutionHostPage />)
  const row = await screen.findByRole('article', { name: 'Workload project-work' })
  fireEvent.click(within(row).getByRole('button', { name: 'Logs' }))
  expect(await screen.findByRole('region', { name: 'Logs for project-work' })).toBeTruthy()
  list.mockResolvedValueOnce({ accepted: true, result: {
    workloads: [{ ...workloads[0], ...(change === 'operation'
      ? { allowedOperations: ['stop'] }
      : { ownership: { grantId: 'replacement-grant', applicationId: null, runId: null }, allowedOperations: ['logs'] }) }, workloads[1]],
  } })
  fireEvent.click(screen.getByRole('button', { name: 'Refresh workloads' }))
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Logs for project-work' })).toBeNull())
  expect(screen.queryByText('retained output')).toBeNull()
})


it('retains sealed development workspace creation and its refused receipt', async () => {
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: { workloads: [] } })
  const create = vi.spyOn(getClient().executionHost, 'createDefaultWorkload').mockResolvedValue({
    accepted: false,
    refusal: { reason: 'workload-spec-not-granted', detail: 'sealed profile mismatch' },
    receipt: { receiptId: 'refused-creation', receiptType: 'stateport.execution-host-operation-receipt/v1', action: 'execution_host.createWorkload', status: 'refused', createdAt: '2026-09-05T00:00:00Z', sourceKind: 'execution_host', operationId: 'create-fixture', requestDigest: 'sha256:1', resultDigest: 'sha256:2', workloadId: 'default-dev' },
  })
  render(<ExecutionHostPage />)
  fireEvent.click(await screen.findByRole('button', { name: 'Create development workspace' }))
  await waitFor(() => expect(create).toHaveBeenCalledExactlyOnceWith())
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('workload-spec-not-granted'))
  expect(screen.getByTestId('execution-host-receipt').textContent).toContain('refused-creation')
  expect(screen.queryByRole('article', { name: 'Workload default-dev' })).toBeNull()
})

it('does not offer duplicate creation while the provisioned workload exists', async () => {
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: { workloads: [{ workloadId: 'default-dev', kind: 'workspace', state: 'stopped' }] } })
  render(<ExecutionHostPage />)
  expect(await screen.findByRole('article', { name: 'Workload default-dev' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Create development workspace' })).toBeNull()
})

it('offers sealed recovery of a removed development container', async () => {
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: { workloads: [{ workloadId: 'default-dev', kind: 'workspace', state: 'removed' }] } })
  const create = vi.spyOn(getClient().executionHost, 'createDefaultWorkload').mockResolvedValue({ accepted: true, result: { workloadId: 'default-dev', state: 'created', recovered: true, recoveredFromState: 'removed' } })
  render(<ExecutionHostPage />)
  expect(await screen.findByRole('article', { name: 'Workload default-dev' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Create development workspace' })).toBeNull()
  expect(screen.getByText(/reattaches the preserved data/)).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Recreate development container' }))
  await waitFor(() => expect(create).toHaveBeenCalledExactlyOnceWith())
})

it('labels truncated log output with the daemon-reported byte bound', async () => {
  vi.spyOn(getClient().executionHost, 'workloadLogs').mockResolvedValue({ accepted: true, result: { output: 'prefix', byteCount: 6, outputByteBound: 6, truncated: true } })
  render(<ExecutionHostPage />)
  fireEvent.click(within(await screen.findByRole('article', { name: 'Workload study-work' })).getByRole('button', { name: 'Logs' }))
  const logs = await screen.findByRole('region', { name: 'Logs for study-work' })
  expect(within(logs).getByText('prefix')).toBeTruthy()
  expect(within(logs).getByText('Output truncated: showing the first 6 bytes (response limit 6 bytes).')).toBeTruthy()
})

it('does not present malformed log output as a complete empty log', async () => {
  vi.spyOn(getClient().executionHost, 'workloadLogs').mockResolvedValue({ accepted: true, result: { unexpected: 'shape' } })
  render(<ExecutionHostPage />)
  fireEvent.click(within(await screen.findByRole('article', { name: 'Workload study-work' })).getByRole('button', { name: 'Logs' }))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('logs could not be loaded'))
  expect(screen.queryByRole('region', { name: 'Logs for study-work' })).toBeNull()
})

it('reloads durable operation history after remount even with an offline daemon and marks failed refresh stale', async () => {
  vi.spyOn(getClient().executionHost, 'status').mockResolvedValue({ status: 'unavailable', grantBound: false })
  const receipts = vi.spyOn(getClient().executionHost, 'listReceipts').mockResolvedValue({ receipts: [{
    receiptId: 'execution-host-prior-stop', receiptType: 'stateport.execution-host-operation-receipt/v1',
    action: 'execution_host.stop', status: 'accepted', createdAt: '2026-09-05T18:00:00Z',
    sourceKind: 'execution_host', payloadDigest: `sha256:${'a'.repeat(64)}`,
  }] })
  const first = render(<ExecutionHostPage />)
  expect(receipts).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Refresh operation history' }))
  expect(await screen.findByText('Receipt: execution-host-prior-stop')).toBeTruthy()
  first.unmount()
  render(<ExecutionHostPage />)
  fireEvent.click(screen.getByRole('button', { name: 'Refresh operation history' }))
  expect(await screen.findByText('Receipt: execution-host-prior-stop')).toBeTruthy()
  expect(receipts).toHaveBeenCalledTimes(2)
  receipts.mockRejectedValueOnce(new Error('offline'))
  fireEvent.click(screen.getByRole('button', { name: 'Refresh operation history' }))
  expect(await screen.findByText(/previous successful read/)).toBeTruthy()
  expect(screen.getByText('Receipt: execution-host-prior-stop')).toBeTruthy()
  expect(screen.queryByText('No runtime operation receipts have been recorded.')).toBeNull()
})

it('creates and recovers the selected application using only its catalog instance', async () => {
  const create = vi.spyOn(getClient().executionHost, 'createDefaultWorkload').mockResolvedValue({ accepted: true })
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: {
    workloads: [{ workloadId: 'study-space', kind: 'workspace', state: 'removed' }],
    defaultWorkspaceRefusal: { reason: 'grant-revoked' },
    applicationWorkspaces: [
      { instanceId: 'project-one', applicationId: 'projectstate', displayName: 'My project', workloadId: 'project-space', status: 'available', allowedOperations: ['createWorkload'] },
      { instanceId: 'study-one', applicationId: 'studystate', displayName: 'My study', workloadId: 'study-space', status: 'available', allowedOperations: ['createWorkload'] },
      { instanceId: 'stale-one', applicationId: 'studystate', workloadId: 'stale-space', status: 'unavailable', reason: 'workspace_binding_stale' },
    ],
  } })
  render(<ExecutionHostPage />)
  const section = await screen.findByRole('region', { name: 'Application workspaces' })
  expect(within(section).getByText(/OS operator issues authority using the installed helper/)).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Create development workspace' })).toHaveProperty('disabled', true)
  const createButtons = within(section).getAllByRole('button', { name: 'Create application workspace' })
  expect(createButtons[1]).toHaveProperty('disabled', true)
  fireEvent.click(createButtons[0])
  await waitFor(() => expect(create).toHaveBeenCalledWith('project-one'))
  await waitFor(() => expect(within(section).getByRole('button', { name: 'Recover application workspace' })).toHaveProperty('disabled', false))
  fireEvent.click(within(section).getByRole('button', { name: 'Recover application workspace' }))
  await waitFor(() => expect(create).toHaveBeenCalledWith('study-one'))
})

it('requires exact approved source review before asking for seeded workspace creation', async () => {
  const reviewDigest = 'sha256:' + 'a'.repeat(64)
  const create = vi.spyOn(getClient().executionHost, 'createDefaultWorkload').mockResolvedValue({ accepted: false, refusal: { reason: 'workspace-seed-unavailable' } })
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: {
    workloads: [], applicationWorkspaces: [{ instanceId: 'project-one', applicationId: 'projectstate', displayName: 'My project', workloadId: 'project-space', status: 'available', allowedOperations: ['createWorkload'], sourceReview: { reviewDigest, baseRevision: 'b'.repeat(40), archiveDigest: 'sha256:' + 'c'.repeat(64), archiveBytes: 10240, fileCount: 1, paths: ['application.yaml'] } }],
  } })
  render(<ExecutionHostPage />)
  fireEvent.click(await screen.findByRole('button', { name: 'Create application workspace' }))
  expect(create).not.toHaveBeenCalled()
  expect(await screen.findByText(/Files: application.yaml/)).toBeTruthy()
  expect(screen.getByText(/Persistent volume byte quotas are unsupported/)).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Confirm approved source' }))
  await waitFor(() => expect(create).toHaveBeenCalledExactlyOnceWith('project-one', reviewDigest))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('workspace-seed-unavailable'))
})


it('links a running bound workspace to the platform terminal without Workbench', async () => {
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: { workloads, applicationWorkspaces: [{ instanceId: 'study-one', applicationId: 'studydd', workloadId: 'project-work', displayName: 'Study workspace', status: 'available' }] } })
  render(<MemoryRouter><ExecutionHostPage /></MemoryRouter>)
  const link = await screen.findByRole('link', { name: 'Open workspace terminal' })
  expect(link.getAttribute('href')).toBe('/execution-host/workspaces/study-one/terminal')
})


it('keeps operator request review reachable without a runtime grant', async () => {
  vi.spyOn(getClient().executionHost, 'status').mockResolvedValue({ status: 'unavailable', grantBound: false })
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: { workloads: [], applicationWorkspaces: [{ instanceId: 'study-one', applicationId: 'studystate', workloadId: '', status: 'unavailable', reason: 'workspace_authority_missing' }] } })
  render(<ExecutionHostPage />)
  expect(await screen.findByRole('button', { name: 'Review workspace authority' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Create application workspace' })).toHaveProperty('disabled', true)
})

it('does not offer a capsule terminal when the exact v2 grant omits terminal operations', async () => {
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: { workloads: [workloads[0]], applicationWorkspaces: [{ instanceId: 'study-one', applicationId: 'studystate', workloadId: 'project-work', status: 'available', terminalAvailable: false, allowedOperations: ['createWorkload', 'listWorkloads', 'execWorkload'] }] } })
  render(<ExecutionHostPage />)
  expect(await screen.findByRole('button', { name: 'Open workspace terminal' })).toHaveProperty('disabled', true)
  expect(screen.queryByRole('link', { name: 'Open workspace terminal' })).toBeNull()
  expect(screen.getByText(/does not include the required terminal operations/)).toBeTruthy()
})

it('keeps application controls independent of an unavailable runtime health probe', async () => {
  const client = getClient().executionHost
  vi.mocked(client.status).mockResolvedValue({ status: 'unavailable', grantBound: false, reason: 'default-grant-missing' })
  const stop = vi.spyOn(client, 'stopWorkload').mockResolvedValue({ accepted: true, result: { workloadId: 'app-space', state: 'stopped' } })
  const create = vi.spyOn(client, 'createDefaultWorkload').mockResolvedValue({ accepted: true, result: { workloadId: 'new-space', state: 'created' } })
  vi.mocked(client.listWorkloads).mockResolvedValue({ accepted: true, result: {
    workloads: [
      { workloadId: 'app-space', kind: 'workspace', state: 'running', ownership: { grantId: 'app-grant', applicationId: 'projectstate', runId: null } },
      { workloadId: 'foreign-space', kind: 'workspace', state: 'running', ownership: { grantId: 'foreign-grant', applicationId: 'other-app', runId: null } },
    ],
    applicationWorkspaces: [
      { instanceId: 'project-one', applicationId: 'projectstate', workloadId: 'app-space', status: 'available', allowedOperations: ['stop', 'cancel', 'removeWorkload', 'logs'] },
      { instanceId: 'new-one', applicationId: 'new-app', workloadId: 'new-space', status: 'available', allowedOperations: ['createWorkload'] },
    ],
  } })
  render(<MemoryRouter><ExecutionHostPage /></MemoryRouter>)
  const section = await screen.findByRole('region', { name: 'Application workspaces' })
  const createButton = within(section).getByRole('button', { name: 'Create application workspace' })
  expect(createButton).toHaveProperty('disabled', false)
  fireEvent.click(createButton)
  await waitFor(() => expect(create).toHaveBeenCalledExactlyOnceWith('new-one'))

  const app = await screen.findByRole('article', { name: 'Workload app-space' })
  const foreign = screen.getByRole('article', { name: 'Workload foreign-space' })
  expect(within(app).getByRole('button', { name: 'Stop' })).toHaveProperty('disabled', false)
  expect(within(foreign).getByRole('button', { name: 'Stop' })).toHaveProperty('disabled', true)
  fireEvent.click(within(app).getByRole('button', { name: 'Stop' }))
  const dialog = await screen.findByRole('alertdialog')
  fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm operation' }))
  await waitFor(() => expect(stop).toHaveBeenCalledExactlyOnceWith('app-space'))
})

it.each(['error', 'refusal'] as const)('keeps creation disabled after inventory %s until a truthful retry', async failure => {
  const client = getClient().executionHost
  const observed = { accepted: true, result: {
    workloads: [{ workloadId: 'project-space', kind: 'workspace', state: 'running' }],
    applicationWorkspaces: [{ instanceId: 'project-one', applicationId: 'projectstate', workloadId: 'project-space', status: 'available', allowedOperations: ['createWorkload'] }],
  } }
  const list = vi.mocked(client.listWorkloads).mockResolvedValue(observed)
  const create = vi.spyOn(client, 'createDefaultWorkload')
  render(<MemoryRouter><ExecutionHostPage /></MemoryRouter>)
  const workload = await screen.findByRole('article', { name: 'Workload project-space' })
  expect(within(workload).getByRole('button', { name: 'Stop' })).toHaveProperty('disabled', false)
  expect(screen.queryByRole('button', { name: 'Create application workspace' })).toBeNull()
  if (failure === 'error') list.mockRejectedValueOnce(new Error('connection lost'))
  else list.mockResolvedValueOnce({ accepted: false, refusal: { reason: 'grant-revoked', detail: 'Inventory denied' } })
  fireEvent.click(screen.getByRole('button', { name: 'Refresh workloads' }))
  await screen.findByRole('alert')
  expect(screen.getByText(/Previous authority observation/)).toBeTruthy()
  const unavailable = screen.getByRole('button', { name: 'Create application workspace' })
  expect(unavailable).toHaveProperty('disabled', true)
  fireEvent.click(unavailable)
  expect(create).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Refresh workloads' }))
  const restored = await screen.findByRole('article', { name: 'Workload project-space' })
  expect(within(restored).getByRole('button', { name: 'Stop' })).toHaveProperty('disabled', false)
  expect(screen.queryByRole('button', { name: 'Create application workspace' })).toBeNull()
  expect(screen.queryByText(/Previous authority observation/)).toBeNull()
  expect(create).not.toHaveBeenCalled()
})

it('initial inventory failure stays unknown until a successful empty observation permits creation', async () => {
  const client = getClient().executionHost
  vi.mocked(client.listWorkloads).mockRejectedValueOnce(new Error('offline')).mockResolvedValue({ accepted: true, result: {
    workloads: [], applicationWorkspaces: [{ instanceId: 'project-one', applicationId: 'projectstate', workloadId: 'project-space', status: 'available', allowedOperations: ['createWorkload'] }],
  } })
  const create = vi.spyOn(client, 'createDefaultWorkload').mockResolvedValue({ accepted: true })
  render(<MemoryRouter><ExecutionHostPage /></MemoryRouter>)
  await screen.findByRole('alert')
  expect(screen.getByText(/Workspace authority and lifecycle are not confirmed/)).toBeTruthy()
  expect(screen.queryByText('No application workspace authority has been provisioned.')).toBeNull()
  expect(screen.queryByRole('button', { name: 'Create development workspace' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Create application workspace' })).toBeNull()
  expect(create).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Refresh workloads' }))
  const button = await screen.findByRole('button', { name: 'Create application workspace' })
  expect(button).toHaveProperty('disabled', false)
  fireEvent.click(button)
  await waitFor(() => expect(create).toHaveBeenCalledExactlyOnceWith('project-one'))
})

it('refuses an open source confirmation when a later poll loses inventory', async () => {
  const client = getClient().executionHost
  const list = vi.mocked(client.listWorkloads).mockResolvedValue({ accepted: true, result: {
    workloads: [], applicationWorkspaces: [{ instanceId: 'project-one', applicationId: 'projectstate', workloadId: 'project-space', status: 'available', allowedOperations: ['createWorkload'],
      sourceReview: { reviewDigest: 'sha256:' + 'a'.repeat(64), baseRevision: 'b'.repeat(40), archiveDigest: 'sha256:' + 'c'.repeat(64), archiveBytes: 10240, fileCount: 1, paths: ['application.yaml'] } }],
  } })
  const create = vi.spyOn(client, 'createDefaultWorkload')
  render(<MemoryRouter><ExecutionHostPage /></MemoryRouter>)
  fireEvent.click(await screen.findByRole('button', { name: 'Create application workspace' }))
  await screen.findByRole('button', { name: 'Confirm approved source' })
  list.mockRejectedValue(new Error('offline'))
  await waitFor(() => expect(screen.getByText(/Workload inventory is unavailable/)).toBeTruthy(), { timeout: 6000 })
  fireEvent.click(screen.getByRole('button', { name: 'Confirm approved source' }))
  await screen.findByText(/Workspace creation or recovery requires a confirmed inventory/)
  expect(create).not.toHaveBeenCalled()
}, 10_000)


it('uses a run-owned workload operation set without borrowing a workspace or default grant', async () => {
  vi.spyOn(getClient().executionHost, 'status').mockResolvedValue({ status: 'unavailable', grantBound: false })
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: {
    workloads: [{ workloadId: 'run-job', kind: 'job', state: 'running',
      ownership: { grantId: 'job-grant', applicationId: 'study', runId: 'run-one' },
      allowedOperations: ['listWorkloads', 'status', 'stop', 'logs'] }],
    applicationWorkspaces: [], defaultWorkspaceRefusal: { reason: 'default_grant_not_configured' },
  } })
  render(<ExecutionHostPage />)
  const row = await screen.findByRole('article', { name: 'Workload run-job' })
  expect(within(row).getByRole('button', { name: 'Stop' })).toHaveProperty('disabled', false)
  expect(within(row).getByRole('button', { name: 'Logs' })).toHaveProperty('disabled', false)
  expect(within(row).getByRole('button', { name: 'Cancel work' })).toHaveProperty('disabled', true)
  expect(within(row).getByRole('button', { name: 'Remove container' })).toHaveProperty('disabled', true)
  expect(screen.getByRole('button', { name: 'Create development workspace' })).toHaveProperty('disabled', true)
})
