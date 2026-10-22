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
const MUTATIONS = ['createDefaultWorkload', 'startWorkload', 'stopWorkload', 'cancelWorkload', 'removeWorkload'] as const

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
  // The agent run panel moved out of this page (agent work belongs to applications).
  expect(screen.queryByRole('region', { name: 'Agent run' })).toBeNull()
})

it('is read-only: no control can create, start, stop, cancel, remove or open a terminal, whatever the grant allows', async () => {
  const client = getClient().executionHost
  const spies = MUTATIONS.map((name) => vi.spyOn(client, name))
  vi.mocked(client.listWorkloads).mockResolvedValue({ accepted: true, result: {
    workloads: [
      { workloadId: 'app-space', kind: 'workspace', state: 'running', ownership: { grantId: 'app-grant', applicationId: 'projectstate', runId: null },
        allowedOperations: ['start', 'stop', 'cancel', 'removeWorkload', 'createWorkload', 'logs'] },
      { workloadId: 'run-job', kind: 'job', state: 'created', ownership: { grantId: 'job-grant', applicationId: 'study', runId: 'run-one' },
        allowedOperations: ['start', 'stop', 'cancel', 'removeWorkload', 'logs'] },
    ],
    applicationWorkspaces: [
      { instanceId: 'project-one', applicationId: 'projectstate', workloadId: 'app-space', status: 'available', terminalAvailable: true,
        allowedOperations: ['createWorkload', 'start', 'stop', 'cancel', 'removeWorkload', 'logs'] },
      { instanceId: 'new-one', applicationId: 'new-app', workloadId: 'new-space', status: 'available', allowedOperations: ['createWorkload'] },
    ],
    defaultWorkspaceRefusal: null,
  } })
  render(<MemoryRouter><ExecutionHostPage /></MemoryRouter>)
  await screen.findByRole('article', { name: 'Workload app-space' })
  const labels = screen.getAllByRole('button').map((button) => button.textContent ?? '')
  for (const forbidden of [/^start$/i, /^stop$/i, /cancel work/i, /remove container/i, /create .*workspace/i, /recover .*workspace/i, /recreate/i, /terminal/i, /prepare/i]) {
    expect(labels.filter((label) => forbidden.test(label)), String(forbidden)).toEqual([])
  }
  expect(screen.queryAllByRole('link', { name: /terminal/i })).toEqual([])
  expect(document.querySelector('a[href*="/terminal"]')).toBeNull()
  // The remaining buttons are reads: refresh, logs, operation history.
  expect(labels.filter((label) => label !== '').sort()).toEqual(
    ['Logs', 'Logs', 'Refresh operation history', 'Refresh status'].sort(),
  )
  for (const spy of spies) expect(spy).not.toHaveBeenCalled()
})

it('shows application workspace status as plain read-only text', async () => {
  vi.mocked(getClient().executionHost.listWorkloads).mockResolvedValue({ accepted: true, result: {
    workloads: [{ workloadId: 'app-space', kind: 'workspace', state: 'running', ownership: { grantId: 'g', applicationId: 'projectstate', runId: null } }],
    applicationWorkspaces: [
      { instanceId: 'project-one', applicationId: 'projectstate', displayName: 'Project One', workloadId: 'app-space', status: 'available', allowedOperations: ['logs'] },
      { instanceId: 'broken-one', applicationId: 'other-app', workloadId: 'gone-space', status: 'unavailable', reason: 'grant-expired' },
    ],
  } })
  render(<MemoryRouter><ExecutionHostPage /></MemoryRouter>)
  const section = await screen.findByRole('region', { name: 'Application workspaces' })
  expect(within(section).getByText('Project One')).toBeTruthy()
  expect(within(section).getByText(/Workspace authority configured/)).toBeTruthy()
  expect(within(section).getByText(/Workspace: running/)).toBeTruthy()
  expect(within(section).getByText(/Unavailable: grant-expired/)).toBeTruthy()
  expect(within(section).queryAllByRole('button')).toEqual([])
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

it('does not treat refused or malformed inventory as empty', async () => {
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: false, refusal: { reason: 'grant-revoked' } })
  const view = render(<ExecutionHostPage />)
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('grant-revoked'))
  expect(screen.getByText(/Workspace status is not confirmed/)).toBeTruthy()
  expect(screen.queryByText('No workloads are visible to this grant.')).toBeNull()
  view.unmount()
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: [] })
  render(<ExecutionHostPage />)
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('inventory is unavailable'))
  expect(screen.queryByText('No workloads are visible to this grant.')).toBeNull()
})

it('says the runtime is unavailable instead of implying work can run', async () => {
  vi.spyOn(getClient().executionHost, 'status').mockResolvedValue({ status: 'unavailable', grantBound: false, reason: 'default-grant-missing' })
  render(<ExecutionHostPage />)
  expect(await screen.findByText(/The execution runtime is not available/)).toBeTruthy()
  expect(screen.getByText(/Status: default-grant-missing/)).toBeTruthy()
})

it('scopes logs to the requested workload and handles transport failures', async () => {
  const logs = vi.spyOn(getClient().executionHost, 'workloadLogs').mockRejectedValue(new Error('transport'))
  render(<ExecutionHostPage />)
  fireEvent.click(within(await screen.findByRole('article', { name: 'Workload study-work' })).getByRole('button', { name: 'Logs' }))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('study-work: logs could not be loaded'))
  expect(logs).toHaveBeenCalledExactlyOnceWith('study-work')
})

it('does not offer logs for a workload the grant does not allow logs for', async () => {
  vi.mocked(getClient().executionHost.listWorkloads).mockResolvedValue({ accepted: true, result: { workloads: [
    { workloadId: 'run-job', kind: 'job', state: 'running', ownership: { grantId: 'job-grant', applicationId: 'study', runId: 'run-one' }, allowedOperations: ['stop'] },
  ] } })
  render(<ExecutionHostPage />)
  const row = await screen.findByRole('article', { name: 'Workload run-job' })
  expect(within(row).getByRole('button', { name: 'Logs' })).toHaveProperty('disabled', true)
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
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
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
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Logs for project-work' })).toBeNull())
  expect(screen.queryByText('retained output')).toBeNull()
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
