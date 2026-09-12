/**
 * useReceipts cadence — the append-only trail has no delta endpoint, so the
 * full list is still re-read; only the cadence is adaptive. Fast (15 s) for a
 * bounded window after a relevant mutation or a manual refresh, slow (60 s)
 * while idle. Initial load, error and highlight semantics are covered by
 * receiptsTool.test.tsx.
 */
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getClient, resetClientForTests } from '@/client'
import { useSessionStore } from '@/state'

import { useReceipts } from '../useReceipts'

const INSTANCE = 'ins_cto_pilot'

beforeEach(() => {
  resetClientForTests()
  vi.useFakeTimers()
  useSessionStore.setState({ operationsMutationCount: 0, operationsRefreshGeneration: 0 })
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.restoreAllMocks()
  resetClientForTests()
})

describe('useReceipts adaptive cadence', () => {
  it('reads at the slow idle cadence and switches to fast after a relevant mutation', async () => {
    const list = vi.spyOn(getClient().receipts, 'list').mockResolvedValue([])
    renderHook(() => useReceipts(INSTANCE))
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(list).toHaveBeenCalledTimes(1)

    // Idle: no refetch before 60 s.
    await act(async () => { await vi.advanceTimersByTimeAsync(59_999) })
    expect(list).toHaveBeenCalledTimes(1)
    await act(async () => { await vi.advanceTimersByTimeAsync(1) })
    expect(list).toHaveBeenCalledTimes(2)

    // A mutation opens the fast window and re-arms the pending slow read.
    const release = useSessionStore.getState().beginOperationsMutation()
    await act(async () => { await vi.advanceTimersByTimeAsync(15_000) })
    expect(list).toHaveBeenCalledTimes(3)
    await act(async () => { await vi.advanceTimersByTimeAsync(15_000) })
    expect(list).toHaveBeenCalledTimes(4)
    release()
  })

  it('returns to the slow cadence once the fast window expires', async () => {
    const list = vi.spyOn(getClient().receipts, 'list').mockResolvedValue([])
    renderHook(() => useReceipts(INSTANCE))
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(list).toHaveBeenCalledTimes(1)

    const release = useSessionStore.getState().beginOperationsMutation()
    // 15 s cadence through the 60 s window: reads at 15/30/45/60 s.
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
    expect(list).toHaveBeenCalledTimes(5)

    await act(async () => { await vi.advanceTimersByTimeAsync(59_999) })
    expect(list).toHaveBeenCalledTimes(5)
    await act(async () => { await vi.advanceTimersByTimeAsync(1) })
    expect(list).toHaveBeenCalledTimes(6)
    release()
  })

  it('opens the fast window on a manual refresh without a duplicate read', async () => {
    const list = vi.spyOn(getClient().receipts, 'list').mockResolvedValue([])
    const view = renderHook(() => useReceipts(INSTANCE))
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(list).toHaveBeenCalledTimes(1)

    act(() => { view.result.current.refresh() })
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(list).toHaveBeenCalledTimes(2)

    await act(async () => { await vi.advanceTimersByTimeAsync(14_999) })
    expect(list).toHaveBeenCalledTimes(2)
    await act(async () => { await vi.advanceTimersByTimeAsync(1) })
    expect(list).toHaveBeenCalledTimes(3)
  })
})
