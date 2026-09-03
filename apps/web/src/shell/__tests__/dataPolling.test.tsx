/**
 * Shell polling honesty — a failed poll must never masquerade as an empty or
 * zero state. After a successful load, a subsequent failure keeps the last
 * known data and exposes an error; a first-load failure renders an honest
 * unavailable indication instead of "0 pending" / "No operations".
 */
import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

import { ClientError, getClient, resetClientForTests, resetMockState } from '@/client'
import { buildSeed } from '@/client/mock/seed'
import { useSessionStore } from '@/state'

import { useOperationsPolling, usePendingApprovalsCount, useUnreadNotificationsCount } from '../data'
import { OperationCenter } from '../OperationCenter'
import { useShellUiStore } from '../shellUi'
import { Topbar } from '../Topbar'
import { NotificationsPopover } from '../NotificationsPopover'

beforeEach(() => {
  resetClientForTests()
  resetMockState()
  useSessionStore.setState({ operations: [], operationsError: null })
  useShellUiStore.setState({ operationCenterOpen: false })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.useRealTimers()
  resetClientForTests()
})

describe('usePendingApprovalsCount', () => {
  it('keeps the last known count and exposes the error when a poll fails', async () => {
    vi.useFakeTimers()
    vi.spyOn(getClient().approvals, 'list')
      .mockResolvedValueOnce([{}, {}] as never)
      .mockRejectedValueOnce(new ClientError('http', 'Forbidden', { status: 403 }))
      .mockResolvedValue([] as never)

    const { result } = renderHook(() => usePendingApprovalsCount())
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(result.current).toEqual({ count: 2, error: null })

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    expect(result.current.count).toBe(2)
    expect(result.current.error).toBeTruthy()

    // Recovery clears the error; a genuine empty list still reports zero.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    expect(result.current).toEqual({ count: 0, error: null })
  })

  it('reports an error, not a confident zero, when the first load fails', async () => {
    vi.useFakeTimers()
    vi.spyOn(getClient().approvals, 'list').mockRejectedValue(new ClientError('http', 'Forbidden', { status: 403 }))

    const { result } = renderHook(() => usePendingApprovalsCount())
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(result.current.error).toBeTruthy()
  })
})

describe('useUnreadNotificationsCount', () => {
  it('keeps the last known count and exposes the error when a poll fails', async () => {
    vi.useFakeTimers()
    vi.spyOn(getClient().activity, 'listNotifications')
      .mockResolvedValueOnce([{ read: false }, { read: false }, { read: true }] as never)
      .mockRejectedValueOnce(new Error('network unreachable'))

    const { result } = renderHook(() => useUnreadNotificationsCount())
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(result.current).toEqual({ count: 2, error: null })

    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000)
    })
    expect(result.current.count).toBe(2)
    expect(result.current.error).toBeTruthy()
  })

  it('reports an error, not a confident zero, when the first load fails', async () => {
    vi.useFakeTimers()
    vi.spyOn(getClient().activity, 'listNotifications').mockRejectedValue(new Error('network unreachable'))

    const { result } = renderHook(() => useUnreadNotificationsCount())
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(result.current.error).toBeTruthy()
  })
})

describe('useOperationsPolling', () => {
  const record = {
    id: 'op_1',
    instanceId: 'inst_1',
    title: 'Apply configuration',
    stageLabel: 'Running',
    state: 'running',
    startedAt: new Date().toISOString(),
    log: [],
  } as never

  it('keeps the last known operations and records the failure when a poll fails', async () => {
    vi.useFakeTimers()
    vi.spyOn(getClient().operations, 'list')
      .mockResolvedValueOnce([record])
      .mockRejectedValueOnce(new Error('network unreachable'))
      .mockResolvedValue([] as never)

    renderHook(() => useOperationsPolling())
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(useSessionStore.getState().operations).toHaveLength(1)
    expect(useSessionStore.getState().operationsError).toBeNull()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_000)
    })
    expect(useSessionStore.getState().operations).toHaveLength(1)
    expect(useSessionStore.getState().operationsError).toBeTruthy()

    // Recovery clears the error; a genuine empty list still replaces the data.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_000)
    })
    expect(useSessionStore.getState().operations).toHaveLength(0)
    expect(useSessionStore.getState().operationsError).toBeNull()
  })
})

describe('OperationCenter', () => {
  it('shows an unavailable state instead of "No operations" when the poll failed', async () => {
    useShellUiStore.setState({ operationCenterOpen: true })
    useSessionStore.setState({ operations: [], operationsError: 'Operations could not be loaded.' })

    render(
      <MemoryRouter>
        <OperationCenter />
      </MemoryRouter>,
    )
    expect(await screen.findByText('Operations unavailable')).toBeTruthy()
    expect(screen.queryByText('No operations')).toBeNull()
  })

  it('keeps showing the last known operations with a stale note after a failed poll', async () => {
    useShellUiStore.setState({ operationCenterOpen: true })
    useSessionStore.setState({
      operations: [
        {
          id: 'op_1',
          instanceId: 'inst_1',
          title: 'Apply configuration',
          stageLabel: 'Running',
          state: 'running',
          startedAt: new Date().toISOString(),
          log: [],
        } as never,
      ],
      operationsError: 'Operations could not be loaded.',
    })

    render(
      <MemoryRouter>
        <OperationCenter />
      </MemoryRouter>,
    )
    expect(await screen.findByTestId('operations-stale')).toBeTruthy()
    expect(screen.getByText('Apply configuration')).toBeTruthy()
    expect(screen.queryByText('Operations unavailable')).toBeNull()
  })

  it('uses the native receipt route when the operation instance has no Workbench', async () => {
    const instance = buildSeed().instances.find(({ id }) => id === 'ins_study_alpha')
    if (!instance) throw new Error('StudyState fixture is missing from the mock seed.')
    vi.spyOn(getClient().applications, 'get').mockResolvedValue(instance)
    useShellUiStore.setState({ operationCenterOpen: true })
    useSessionStore.setState({
      operations: [
        {
          id: 'op_receipt',
          instanceId: instance.id,
          title: 'Study operation',
          stageLabel: 'Complete',
          state: 'completed',
          startedAt: new Date().toISOString(),
          log: [],
          relatedReceiptId: 'rcpt_0004',
        },
      ] as never,
      operationsError: null,
    })

    render(
      <MemoryRouter>
        <OperationCenter />
      </MemoryRouter>,
    )
    const link = await screen.findByRole('link', { name: 'Receipt' })
    expect(link.getAttribute('href')).toBe('/app/ins_study_alpha/receipts/rcpt_0004')
  })

  it('still shows the genuine empty state when the poll succeeded with no operations', async () => {
    useShellUiStore.setState({ operationCenterOpen: true })
    useSessionStore.setState({ operations: [], operationsError: null })

    render(
      <MemoryRouter>
        <OperationCenter />
      </MemoryRouter>,
    )
    expect(await screen.findByText('No operations')).toBeTruthy()
  })
})

describe('Topbar badges', () => {
  it('renders an indeterminate indication instead of 0 when the counts cannot be fetched', async () => {
    vi.spyOn(getClient().approvals, 'list').mockRejectedValue(new ClientError('http', 'Forbidden', { status: 403 }))
    vi.spyOn(getClient().activity, 'listNotifications').mockRejectedValue(new Error('network unreachable'))

    render(
      <MemoryRouter>
        <Topbar />
      </MemoryRouter>,
    )
    expect(await screen.findByLabelText('Approvals, count unavailable')).toBeTruthy()
    expect(await screen.findByLabelText('Notifications, count unavailable')).toBeTruthy()
    expect(screen.queryByLabelText('Approvals')).toBeNull()
  })
})

describe('NotificationsPopover', () => {
  it('shows unavailable with Retry instead of an empty notification state', async () => {
    const list = vi.spyOn(getClient().activity, 'listNotifications')
      .mockRejectedValueOnce(new Error('notification source unavailable'))
      .mockResolvedValueOnce([])

    render(
      <MemoryRouter>
        <NotificationsPopover>
          <button type="button">Open notifications</button>
        </NotificationsPopover>
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Open notifications' }))
    expect(await screen.findByTestId('notifications-unavailable')).toBeTruthy()
    expect(screen.getByText('Notifications unavailable')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2))
    expect(await screen.findByText('No notifications')).toBeTruthy()
  })

  it('marks a notification read with its owning instance id', async () => {
    const notification = {
      id: 'attention-study',
      instanceId: 'ins_study_alpha',
      title: 'Review the next activity',
      body: 'A study activity is waiting for review.',
      importance: 'important' as const,
      createdAt: '2026-08-09T12:00:00.000Z',
      read: false,
      acknowledged: false,
    }
    vi.spyOn(getClient().activity, 'listNotifications').mockResolvedValue([notification])
    const markRead = vi.spyOn(getClient().activity, 'markNotificationRead').mockResolvedValue(undefined)

    render(
      <MemoryRouter>
        <NotificationsPopover>
          <button type="button">Open notifications</button>
        </NotificationsPopover>
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Open notifications' }))
    await userEvent.click(await screen.findByRole('button', { name: /Review the next activity/ }))

    await waitFor(() => {
      expect(markRead).toHaveBeenCalledWith('attention-study', { instanceId: 'ins_study_alpha' })
    })
  })
})
