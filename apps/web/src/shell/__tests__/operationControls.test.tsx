import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ClientError, getClient, resetClientForTests, resetMockState } from '@/client'
import type { OperationRecord } from '@/client'
import { useSessionStore } from '@/state'

import { OperationCenter } from '../OperationCenter'
import { useShellUiStore } from '../shellUi'

const operation: OperationRecord = {
  id: 'op_run_1', instanceId: 'ins_study_alpha', kind: 'orchestration_run',
  title: 'Validate study', state: 'awaiting_approval', stageLabel: 'Awaiting approval',
  startedAt: '2026-09-06T00:00:00Z', updatedAt: '2026-09-06T00:00:00Z',
  canPause: false, canCancel: true, log: [], relatedReceiptId: 'rcpt_0004',
}

beforeEach(() => {
  resetClientForTests()
  resetMockState()
  useSessionStore.setState({ operations: [], operationsError: null })
  useShellUiStore.setState({ operationCenterOpen: true })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  resetClientForTests()
})

function show(record: OperationRecord) {
  useSessionStore.setState({ operations: [record] })
  render(<MemoryRouter><OperationCenter /></MemoryRouter>)
}

describe('Operation center action authority and failures', () => {
  it.each(['awaiting_approval', 'approved', 'prepared', 'interrupted', 'running', 'cancelling'] as const)(
    'offers service-supported cancellation in %s', async (state) => {
      const cancel = vi.spyOn(getClient().operations, 'cancel').mockResolvedValue({
        ...operation, state: 'cancelled', canCancel: false,
      })
      show({ ...operation, state })
      await userEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
      expect(cancel).toHaveBeenCalledExactlyOnceWith(operation.id)
      await waitFor(() => expect(useSessionStore.getState().operations[0].state).toBe('cancelled'))
      expect(screen.queryByRole('button', { name: 'Cancel' })).toBeNull()
    },
  )

  it('does not infer cancellation authority from a running state', () => {
    show({ ...operation, state: 'running', canCancel: false })
    expect(screen.queryByRole('button', { name: 'Cancel' })).toBeNull()
  })

  it.each([403, 409])('retains an unconfirmed action after HTTP %s across a successful poll until deliberate retry', async (status) => {
    const cancel = vi.spyOn(getClient().operations, 'cancel')
      .mockRejectedValueOnce(new ClientError('http', 'Refused', { status }))
      .mockResolvedValueOnce({ ...operation, state: 'cancelled', canCancel: false })
    show(operation)
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    expect((await screen.findByRole('alert')).textContent).toBe(
      'Cancellation could not be confirmed. Check the current operation state before retrying.',
    )
    expect(useSessionStore.getState().operations[0]).toEqual(operation)
    // A successful unrelated status refresh must not erase the mutation failure.
    act(() => useSessionStore.setState({
      operations: [{ ...operation, updatedAt: '2026-09-06T00:00:03Z', stageLabel: 'Still awaiting approval' }],
      operationsError: null,
    }))
    expect(screen.getByRole('alert').textContent).toContain('Cancellation could not be confirmed')
    expect(useSessionStore.getState().operations[0].relatedReceiptId).toBe(operation.relatedReceiptId)
    expect(cancel).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(useSessionStore.getState().operations[0].state).toBe('cancelled'))
    expect(cancel).toHaveBeenCalledTimes(2)
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('reports an unconfirmed pause without claiming unchanged service state', async () => {
    vi.spyOn(getClient().operations, 'pause').mockRejectedValue(new Error('Response lost'))
    show({ ...operation, state: 'running', canPause: true })
    await userEvent.click(await screen.findByRole('button', { name: 'Pause' }))
    expect((await screen.findByRole('alert')).textContent).toBe(
      'Pause could not be confirmed. Check the current operation state before retrying.',
    )
    expect(useSessionStore.getState().operations[0].state).toBe('running')
  })
})


it('shows observation refusal alongside real operations without invented execution information', () => {
  useSessionStore.setState({ operations: [operation, {
    id: 'observation_infra', instanceId: 'legacy', kind: 'infrastructure_observation',
    title: 'Infrastructure operations unavailable', observationError: 'Repository ownership cannot be confirmed',
  }] })
  render(<MemoryRouter><OperationCenter /></MemoryRouter>)
  const observation = within(screen.getByTestId('operation-observation'))
  expect(observation.getByRole('alert').textContent).toContain('ownership cannot be confirmed')
  expect(observation.queryByRole('button')).toBeNull()
  expect(observation.queryByText(/Started/)).toBeNull()
  expect(observation.queryByRole('progressbar')).toBeNull()
  expect(observation.queryByLabelText('Progress indeterminate')).toBeNull()
  expect(screen.getByRole('button', { name: 'Cancel' })).toBeTruthy()
})
