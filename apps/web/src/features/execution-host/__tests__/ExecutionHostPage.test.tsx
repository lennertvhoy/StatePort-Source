import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { getClient, resetClientForTests } from '@/client'
import ExecutionHostPage from '../ExecutionHostPage'

const workloads = [
  { workloadId: 'project-work', kind: 'workspace', state: 'running', imageDigest: 'sha256:project' },
  { workloadId: 'study-work', kind: 'job', state: 'created', imageDigest: 'sha256:study' },
]
beforeEach(() => {
  resetClientForTests()
  vi.spyOn(getClient().executionHost, 'status').mockResolvedValue({ status: 'available', grantBound: true, grantId: 'control-plane-default' })
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: { workloads } })
})
afterEach(() => { cleanup(); vi.restoreAllMocks(); resetClientForTests() })

it('renders every granted workload from the actual daemon object contract', async () => {
  render(<ExecutionHostPage />)
  expect(await screen.findByRole('article', { name: 'Workload project-work' })).toBeTruthy()
  expect(screen.getByRole('article', { name: 'Workload study-work' })).toBeTruthy()
  expect(screen.getByText('Image: sha256:project')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Run verification' })).toBeNull()
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

it('does not offer unsupported recreation of a removed workload ID', async () => {
  vi.spyOn(getClient().executionHost, 'listWorkloads').mockResolvedValue({ accepted: true, result: { workloads: [{ workloadId: 'default-dev', kind: 'workspace', state: 'removed' }] } })
  render(<ExecutionHostPage />)
  expect(await screen.findByRole('article', { name: 'Workload default-dev' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Create development workspace' })).toBeNull()
  expect(screen.getByText(/recreating this workload ID is not supported here/)).toBeTruthy()
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
