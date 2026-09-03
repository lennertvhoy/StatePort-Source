/**
 * DeploymentsNavPanel honesty — a failed poll must never render as "No target
 * verified." / "No plans yet." After a successful load, a subsequent failure
 * keeps the last known target and plans and flags them as stale; a first-load
 * failure surfaces an honest unavailable state.
 */
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ClientError, getClient, resetClientForTests, resetMockState } from '@/client'
import { INSTANCE_IDS } from '@/client/mock/seed'

import { DeploymentsNavPanel } from '../DeploymentsNavPanel'

const NIXOS = INSTANCE_IDS.nixosInfra

function renderPanel() {
  return render(<DeploymentsNavPanel instanceId={NIXOS} tool="deployments" />)
}

beforeEach(() => {
  resetClientForTests()
  resetMockState()
  vi.useFakeTimers()
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.useRealTimers()
  resetClientForTests()
})

describe('DeploymentsNavPanel', () => {
  it('keeps the last known target and flags it stale when a poll fails', async () => {
    renderPanel()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000)
    })
    expect(screen.getByTestId('nav-target-row')).toBeTruthy()
    expect(screen.queryByTestId('nav-deployments-stale')).toBeNull()

    vi.spyOn(getClient().infrastructure, 'getTarget').mockRejectedValue(
      new ClientError('http', 'Forbidden', { status: 403 }),
    )
    vi.spyOn(getClient().infrastructure, 'listPlans').mockRejectedValue(new Error('network unreachable'))

    await act(async () => {
      await vi.advanceTimersByTimeAsync(11_000)
    })
    // The previously loaded target is not erased and the failure is surfaced.
    expect(screen.getByTestId('nav-target-row')).toBeTruthy()
    expect(screen.getByTestId('nav-deployments-stale')).toBeTruthy()
    expect(screen.queryByText('No target verified.')).toBeNull()
    expect(screen.queryByText('No plans yet.')).toBeNull()
  })

  it('shows an honest unavailable state when the first load fails', async () => {
    vi.spyOn(getClient().infrastructure, 'getTarget').mockRejectedValue(
      new ClientError('http', 'Forbidden', { status: 403 }),
    )
    vi.spyOn(getClient().infrastructure, 'listPlans').mockRejectedValue(
      new ClientError('http', 'Forbidden', { status: 403 }),
    )
    renderPanel()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000)
    })

    expect(screen.getByTestId('nav-target-unavailable')).toBeTruthy()
    expect(screen.getByTestId('nav-plans-unavailable')).toBeTruthy()
    expect(screen.queryByText('No target verified.')).toBeNull()
    expect(screen.queryByText('No plans yet.')).toBeNull()
  })
})
