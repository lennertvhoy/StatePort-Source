import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests } from '@/client'

import ExecutionHostPage from '../ExecutionHostPage'

const RECEIPT = {
  receiptId: 'execution-host-op-fixture',
  receiptType: 'stateport.execution-host-operation-receipt/v1' as const,
  action: 'execution_host.createWorkload',
  status: 'accepted' as const,
  createdAt: '2026-08-20T00:00:00Z',
  sourceKind: 'execution_host' as const,
  actorId: 'local-user',
  operationId: 'op-fixture',
  requestDigest: `sha256:${'1'.repeat(64)}`,
  resultDigest: `sha256:${'2'.repeat(64)}`,
  workloadId: 'default-dev',
}

beforeEach(() => {
  resetClientForTests()
  const client = getClient()
  vi.spyOn(client.executionHost, 'status').mockResolvedValue({
    status: 'available',
    contractVersion: 1,
    engine: 'podman',
    grantId: 'control-plane-default',
    grantBound: true,
  })
  vi.spyOn(client.executionHost, 'listReceipts').mockResolvedValue({ receipts: [] })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  resetClientForTests()
})

describe('ExecutionHostPage J1 journey', () => {
  it('creates only the canonical default workspace and renders its persisted receipt', async () => {
    const client = getClient()
    vi.spyOn(client.executionHost, 'listWorkloads').mockResolvedValue({
      accepted: true,
      result: [],
    })
    vi.spyOn(client.executionHost, 'workloadStatus')
      .mockResolvedValueOnce({
        accepted: true,
        result: { workloadId: 'default-dev', state: 'created' },
      })
      .mockResolvedValue({
        accepted: true,
        result: { workloadId: 'default-dev', state: 'running' },
      })
    const create = vi.spyOn(client.executionHost, 'createDefaultWorkload').mockResolvedValue({
      operationId: 'op-fixture',
      accepted: true,
      result: { workloadId: 'default-dev', state: 'created' },
      receipt: RECEIPT,
    })
    const start = vi.spyOn(client.executionHost, 'startWorkload').mockResolvedValue({
      operationId: 'op-start',
      accepted: true,
      result: { workloadId: 'default-dev', state: 'running' },
      receipt: {
        ...RECEIPT,
        receiptId: 'execution-host-op-start',
        operationId: 'op-start',
        action: 'execution_host.start',
      },
    })
    const exec = vi.spyOn(client.executionHost, 'execWorkload').mockResolvedValue({
      operationId: 'op-exec',
      accepted: true,
      result: { workloadId: 'default-dev', state: 'running', output: 'stateport-j1-ok\n' },
      receipt: {
        ...RECEIPT,
        receiptId: 'execution-host-op-exec',
        operationId: 'op-exec',
        action: 'execution_host.execWorkload',
      },
    })

    render(<ExecutionHostPage />)
    fireEvent.click(await screen.findByRole('button', { name: 'Create default workspace' }))

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    fireEvent.click(await screen.findByRole('button', { name: 'Start' }))
    await waitFor(() => expect(start).toHaveBeenCalledWith('default-dev'))
    const runVerification = await screen.findByRole('button', { name: 'Run verification' })
    await waitFor(() => expect((runVerification as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(runVerification)
    await waitFor(() =>
      expect(exec).toHaveBeenCalledWith('default-dev', [
        '/bin/sh',
        '-lc',
        "printf 'stateport-j1-ok\\n'",
      ]),
    )
    expect(await screen.findByText('stateport-j1-ok')).toBeTruthy()
    const receipt = await screen.findByTestId('execution-host-receipt')
    expect(receipt.textContent).toContain('execution-host-op-exec')
    expect(receipt.textContent).toContain('execution_host.execWorkload')
  })

  it('executes the fixed verification command and renders bounded output', async () => {
    const client = getClient()
    vi.spyOn(client.executionHost, 'listWorkloads').mockResolvedValue({
      accepted: true,
      result: [{ workloadId: 'default-dev' }],
    })
    vi.spyOn(client.executionHost, 'workloadStatus').mockResolvedValue({
      accepted: true,
      result: { workloadId: 'default-dev', state: 'running' },
    })
    const exec = vi.spyOn(client.executionHost, 'execWorkload').mockResolvedValue({
      operationId: 'op-exec',
      accepted: true,
      result: { workloadId: 'default-dev', state: 'running', output: 'stateport-j1-ok\n' },
      receipt: { ...RECEIPT, receiptId: 'execution-host-op-exec', operationId: 'op-exec', action: 'execution_host.execWorkload' },
    })

    render(<ExecutionHostPage />)
    fireEvent.click(await screen.findByRole('button', { name: 'Run verification' }))

    await waitFor(() =>
      expect(exec).toHaveBeenCalledWith('default-dev', [
        '/bin/sh',
        '-lc',
        "printf 'stateport-j1-ok\\n'",
      ]),
    )
    expect(await screen.findByText('stateport-j1-ok')).toBeTruthy()
    expect((await screen.findByTestId('execution-host-receipt')).textContent).toContain(
      'execution_host.execWorkload',
    )
  })

  it('renders a daemon refusal instead of inventing lifecycle state', async () => {
    const client = getClient()
    vi.spyOn(client.executionHost, 'listWorkloads').mockResolvedValue({
      accepted: true,
      result: [],
    })
    vi.spyOn(client.executionHost, 'createDefaultWorkload').mockResolvedValue({
      accepted: false,
      refusal: { reason: 'workload-spec-not-granted', detail: 'sealed digest mismatch' },
    })

    render(<ExecutionHostPage />)
    fireEvent.click(await screen.findByRole('button', { name: 'Create default workspace' }))

    expect(await screen.findByText(/workload-spec-not-granted/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Create default workspace' })).toBeTruthy()
  })

  it('does not treat a refused workload inventory as an empty inventory', async () => {
    const client = getClient()
    vi.spyOn(client.executionHost, 'listWorkloads').mockResolvedValue({
      accepted: false,
      refusal: { reason: 'grant-revoked', detail: 'inventory access refused' },
    })

    render(<ExecutionHostPage />)

    expect(await screen.findByText(/grant-revoked/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Create default workspace' })).toBeNull()
  })
})
