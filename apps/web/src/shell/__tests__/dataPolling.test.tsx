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

import type { InfrastructureTarget } from '@/client'
import { ClientError, getClient, resetClientForTests, resetMockState } from '@/client'
import { buildSeed, INSTANCE_IDS } from '@/client/mock/seed'
import { useSessionStore } from '@/state'
import { useRuns } from '@/features/runs/useRuns'

import { hasLiveOperation, useOperationsPolling, usePendingApprovalsCount, useSharedInfrastructureTarget, useUnreadNotificationsCount } from '../data'
import { OperationCenter } from '../OperationCenter'
import { useShellUiStore } from '../shellUi'
import { Topbar } from '../Topbar'
import { NotificationsPopover } from '../NotificationsPopover'

beforeEach(() => {
  resetClientForTests()
  resetMockState()
  useSessionStore.setState({ operations: [], operationsError: null, operationsRefreshGeneration: 0, operationsMutationCount: 0 })
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

  it.each([
    'draft', 'proposed', 'preparing', 'prepared', 'awaiting_approval', 'approved',
    'queued', 'running', 'cancelling', 'paused', 'interrupted', 'validating',
  ])('keeps the active cadence for %s operations', (state) => {
    expect(hasLiveOperation([{ state }])).toBe(true)
  })

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

  it('uses a slow idle cadence and returns to the active cadence for live work', async () => {
    vi.useFakeTimers()
    const list = vi.spyOn(getClient().operations, 'list')
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([record])
      .mockResolvedValue([] as never)

    renderHook(() => useOperationsPolling())
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(list).toHaveBeenCalledTimes(1)

    await act(async () => { await vi.advanceTimersByTimeAsync(29_999) })
    expect(list).toHaveBeenCalledTimes(1)
    await act(async () => { await vi.advanceTimersByTimeAsync(1) })
    expect(list).toHaveBeenCalledTimes(2)

    // The live response keeps the short cadence.
    await act(async () => { await vi.advanceTimersByTimeAsync(2_999) })
    expect(list).toHaveBeenCalledTimes(2)
    await act(async () => { await vi.advanceTimersByTimeAsync(1) })
    expect(list).toHaveBeenCalledTimes(3)
  })

  it('wakes an idle poll immediately when a mutation requests a refresh', async () => {
    vi.useFakeTimers()
    const list = vi.spyOn(getClient().operations, 'list')
      .mockResolvedValueOnce([])
      .mockResolvedValue([] as never)

    renderHook(() => useOperationsPolling())
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(list).toHaveBeenCalledTimes(1)

    act(() => {
      useSessionStore.getState().upsertOperation({ ...(record as Record<string, unknown>), state: 'cancelling' } as never)
    })
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(list).toHaveBeenCalledTimes(2)
  })

  it('wakes the operations projection when a run mutation starts', async () => {
    vi.useFakeTimers()
    const list = vi.spyOn(getClient().operations, 'list')
      .mockResolvedValueOnce([])
      .mockResolvedValue([] as never)
    vi.spyOn(getClient().runs, 'listActions').mockResolvedValue([])
    vi.spyOn(getClient().runs, 'listEngines').mockResolvedValue([])
    vi.spyOn(getClient().runs, 'getHistory').mockResolvedValue([])
    let finishPrepare!: (run: never) => void
    vi.spyOn(getClient().runs, 'prepare').mockImplementation(
      () => new Promise((resolve) => { finishPrepare = resolve }),
    )

    const { result } = renderHook(() => ({ polling: useOperationsPolling(), runs: useRuns('inst_1') }))
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(list).toHaveBeenCalledTimes(1)

    let prepare!: Promise<unknown>
    act(() => {
      prepare = result.current.runs.prepare({ actionId: 'act_1', engineId: 'engine_1', inputs: {} })
    })
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(list).toHaveBeenCalledTimes(2)
    // The delayed mutation keeps polling at the active cadence even though
    // its start wake still saw an empty projection.
    await act(async () => { await vi.advanceTimersByTimeAsync(3_000) })
    expect(list).toHaveBeenCalledTimes(3)

    await act(async () => {
      finishPrepare({ id: 'run_1', instanceId: 'inst_1' } as never)
      await prepare
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(list).toHaveBeenCalledTimes(4)
  })

  it('releases overlapping mutation holds independently and idempotently', () => {
    const first = useSessionStore.getState().beginOperationsMutation()
    const second = useSessionStore.getState().beginOperationsMutation()
    expect(useSessionStore.getState().operationsMutationCount).toBe(2)

    first()
    first()
    expect(useSessionStore.getState().operationsMutationCount).toBe(1)
    second()
    expect(useSessionStore.getState().operationsMutationCount).toBe(0)
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

  it('keeps a refreshed unread notification when an older read completes late', async () => {
    const notification = { id: 'recovery-backup', instanceId: 'ins_1', title: 'Backup needed',
      importance: 'important' as const, createdAt: '2026-08-09T12:00:00.000Z', read: false, acknowledged: false }
    let finish!: () => void
    vi.spyOn(getClient().activity, 'listNotifications').mockResolvedValue([notification])
    vi.spyOn(getClient().activity, 'markNotificationRead').mockImplementation(() => new Promise(resolve => { finish = resolve }))
    render(<MemoryRouter><NotificationsPopover><button type="button">Open notifications</button></NotificationsPopover></MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: 'Open notifications' }))
    await userEvent.click(await screen.findByRole('button', { name: /Backup needed/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Open notifications' }))
    await screen.findByRole('button', { name: /Backup needed/ })
    await act(async () => { finish() })
    expect(screen.getByLabelText('Unread')).toBeTruthy()
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

describe('useSharedInfrastructureTarget', () => {
  it('serves every subscriber from one 10 s poll and stops with the last', async () => {
    vi.useFakeTimers()
    const getTarget = vi.spyOn(getClient().infrastructure, 'getTarget')

    const first = renderHook(() => useSharedInfrastructureTarget(INSTANCE_IDS.nixosInfra, true))
    const second = renderHook(() => useSharedInfrastructureTarget(INSTANCE_IDS.nixosInfra, true))
    expect(getTarget).toHaveBeenCalledTimes(1)

    await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
    expect(getTarget).toHaveBeenCalledTimes(2)
    expect(first.result.current.target?.name).toBeTruthy()
    expect(first.result.current.target).toEqual(second.result.current.target)

    first.unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
    expect(getTarget).toHaveBeenCalledTimes(3)

    second.unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
    expect(getTarget).toHaveBeenCalledTimes(3)
  })

  it('keeps the last known target and exposes the failure when a poll fails', async () => {
    vi.useFakeTimers()
    const target = {
      id: 'tgt_1',
      instanceId: INSTANCE_IDS.nixosInfra,
      name: 'homelab-dev',
    } as InfrastructureTarget
    vi.spyOn(getClient().infrastructure, 'getTarget')
      .mockResolvedValueOnce(target)
      .mockRejectedValue(new Error('network unreachable'))

    const view = renderHook(() => useSharedInfrastructureTarget(INSTANCE_IDS.nixosInfra, true))
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(view.result.current).toEqual({ target, error: null })

    await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
    expect(view.result.current.target).toEqual(target)
    expect(view.result.current.error).toBeTruthy()
  })

  it('does not poll while disabled', async () => {
    vi.useFakeTimers()
    const getTarget = vi.spyOn(getClient().infrastructure, 'getTarget')
    renderHook(() => useSharedInfrastructureTarget(INSTANCE_IDS.nixosInfra, false))
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
    expect(getTarget).not.toHaveBeenCalled()
  })
})

describe('shared chrome observations', () => {
  it('shares requests across surfaces, skips overlap, and stops after the last surface unmounts', async () => {
    vi.useFakeTimers()
    let finish!: (value: never[]) => void
    const request = vi.spyOn(getClient().approvals, 'list')
      .mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
      .mockResolvedValue([])
    const first = renderHook(() => usePendingApprovalsCount())
    const second = renderHook(() => usePendingApprovalsCount())
    const third = renderHook(() => usePendingApprovalsCount())
    expect(request).toHaveBeenCalledTimes(1)
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
    expect(request).toHaveBeenCalledTimes(1)
    await act(async () => { finish([]) })
    first.unmount()
    second.unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
    expect(request).toHaveBeenCalledTimes(2)
    expect(third.result.current).toEqual({ count: 0, error: null })
    third.unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
    expect(request).toHaveBeenCalledTimes(2)
  })

  it('discards a late response from a previous subscription', async () => {
    let finish!: (value: never[]) => void
    const request = vi.spyOn(getClient().activity, 'listNotifications')
      .mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
      .mockResolvedValue([])
    const first = renderHook(() => useUnreadNotificationsCount())
    first.unmount()
    const second = renderHook(() => useUnreadNotificationsCount())
    await act(async () => { finish([{ read: false }] as never[]) })
    expect(request).toHaveBeenCalledTimes(2)
    expect(second.result.current).toEqual({ count: 0, error: null })
  })
})


it('coalesces a refresh while a previous operation poll is pending and stops on unmount', async () => {
  vi.useFakeTimers()
  const resolves: Array<(records: []) => void> = []
  const list = vi.spyOn(getClient().operations, 'list').mockImplementation(() => new Promise<[]>((done) => { resolves.push(done) }))
  const hook = renderHook(() => useOperationsPolling())
  expect(list).toHaveBeenCalledTimes(1)

  act(() => {
    useSessionStore.getState().requestOperationsRefresh()
    useSessionStore.getState().requestOperationsRefresh()
  })
  expect(list).toHaveBeenCalledTimes(1)

  await act(async () => { resolves[0]!([]); await vi.advanceTimersByTimeAsync(0) })
  expect(list).toHaveBeenCalledTimes(2)
  hook.unmount()
  await act(async () => { resolves[1]!([]); await vi.advanceTimersByTimeAsync(60_000) })
  expect(list).toHaveBeenCalledTimes(2)
})
