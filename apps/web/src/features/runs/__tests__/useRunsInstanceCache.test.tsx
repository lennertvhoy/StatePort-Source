/**
 * Instance-state truth after governed run transitions (row #22).
 *
 * The shell caches each instance projection (`fetchInstanceCached`) and the
 * app context shell holds it for the current route. A run transition that
 * lands from the Runs surface (apply, proposal-approve, cancel) changes the
 * durable instance state server-side, so the affected instance's cached
 * projection must be dropped and the live context re-read — otherwise the
 * Learning overview keeps showing the pre-transition progress until a hard
 * reload.
 */
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ApplicationInstance, RunOperation, RunRecord, StudyStatePackageData } from '@/client'
import { getClient, resetClientForTests } from '@/client'
import { InstanceContext, type CurrentInstanceContext } from '@/shell/currentInstance'
import { fetchInstanceCached, invalidateInstanceCache } from '@/shell/data'
import { useSessionStore } from '@/state'

import { useRuns } from '../useRuns'

const INSTANCE = 'ins_1a2b3c4d5e6f7089'

const study: StudyStatePackageData = {
  kind: 'study-state',
  goal: 'Learn the governed evidence loop',
  goalProgressPercent: 50,
  planDigest: `sha256:${'a'.repeat(64)}`,
  canUndo: false,
  activities: [
    {
      id: 'evidence-practice',
      title: 'Complete one evidence-backed practice activity',
      state: 'paused',
      updatedAt: '2026-09-30T12:00:00Z',
    },
  ],
  evidence: [],
}

function instanceWithProgress(percent: number): ApplicationInstance {
  return {
    id: INSTANCE,
    name: 'StudyState Sample',
    packageId: 'studystate.sample',
    packageName: 'studystate.sample',
    packageDisplayName: 'StudyState Sample',
    health: 'ready',
    attention: [],
    recentActivity: [],
    settings: {
      instanceId: INSTANCE,
      notificationLevel: 'inherit',
      conversation: { defaultContext: [] },
      backup: { enabled: false, intervalHours: 24 },
      terminal: {},
    },
    capabilities: [{ id: 'goal_execution', status: 'available' }],
    receiptIds: [],
    recovery: { state: 'not_configured' },
    packageState: { ...study, goalProgressPercent: percent },
    pinned: false,
    createdAt: '2026-09-30T12:00:00Z',
  }
}

/** `packageState` is a union; only the study-state arm carries the goal percent. */
function studyProgress(instance: ApplicationInstance): number | undefined {
  const state = instance.packageState
  return state?.kind === 'study-state' ? state.goalProgressPercent : undefined
}

function runRecord(status: RunRecord['status'], revision: number): RunRecord {
  return {
    id: 'run-cache-1',
    instanceId: INSTANCE,
    actionId: 'studystate.sample.start-activity/v1',
    engineId: 'synthetic',
    state: status === 'applied' ? 'applied' : 'awaiting_approval',
    status,
    revision,
    inputs: {},
    createdAt: '2026-09-30T12:00:00Z',
    updatedAt: '2026-09-30T12:00:00Z',
  }
}

function contextWithRefresh(refresh: () => void): CurrentInstanceContext {
  return {
    instance: null,
    capabilities: new Map(),
    loading: false,
    error: null,
    refresh,
    hasCapability: () => false,
    capability: () => undefined,
  }
}

beforeEach(() => {
  resetClientForTests()
  invalidateInstanceCache()
  useSessionStore.setState({ operationsMutationCount: 0 })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  resetClientForTests()
  invalidateInstanceCache()
  useSessionStore.setState({ operationsMutationCount: 0 })
})

describe('useRuns instance-cache invalidation', () => {
  it.each(['apply', 'proposal-approve', 'cancel'] as const)(
    'drops the cached instance projection and re-reads the context after a successful %s',
    async (operation) => {
      let progress = 50
      const applicationsGet = vi.spyOn(getClient().applications, 'get')
      applicationsGet.mockImplementation(async () => instanceWithProgress(progress))
      vi.spyOn(getClient().runs, 'listActions').mockResolvedValue([])
      vi.spyOn(getClient().runs, 'listEngines').mockResolvedValue([])
      vi.spyOn(getClient().runs, 'getHistory').mockResolvedValue([])
      const transition = vi.spyOn(getClient().runs, 'transition').mockImplementation(
        async (_id: string, op: RunOperation) =>
          runRecord(op === 'apply' ? 'applied' : op === 'cancel' ? 'cancelled' : 'state_change_approved', 9),
      )
      const refreshContext = vi.fn()

      // The Learning overview's read primes the shell instance cache.
      const before = await fetchInstanceCached(INSTANCE)
      expect(studyProgress(before)).toBe(50)

      const view = renderHook(() => useRuns(INSTANCE), {
        wrapper: ({ children }) => (
          <InstanceContext.Provider value={contextWithRefresh(refreshContext)}>
            {children}
          </InstanceContext.Provider>
        ),
      })
      await act(async () => {}) // let the initial runs load land

      await act(async () => {
        await view.result.current.transition(runRecord('awaiting_approval', 8), operation)
      })
      expect(transition).toHaveBeenCalledTimes(1)

      // The projection changed server-side; the next read must re-fetch.
      progress = 100
      const after = await fetchInstanceCached(INSTANCE)
      expect(applicationsGet).toHaveBeenCalledTimes(2)
      expect(studyProgress(after)).toBe(100)
      expect(refreshContext).toHaveBeenCalledTimes(1)
    },
  )

  it('does not re-read the context when the transition targets another instance', async () => {
    vi.spyOn(getClient().applications, 'get').mockResolvedValue(instanceWithProgress(50))
    vi.spyOn(getClient().runs, 'listActions').mockResolvedValue([])
    vi.spyOn(getClient().runs, 'listEngines').mockResolvedValue([])
    vi.spyOn(getClient().runs, 'getHistory').mockResolvedValue([])
    const other = 'ins_other_instance00'
    vi.spyOn(getClient().runs, 'transition').mockResolvedValue({
      ...runRecord('applied', 9),
      instanceId: other,
    })
    const refreshContext = vi.fn()

    const view = renderHook(() => useRuns(INSTANCE), {
      wrapper: ({ children }) => (
        <InstanceContext.Provider value={contextWithRefresh(refreshContext)}>
          {children}
        </InstanceContext.Provider>
      ),
    })
    await act(async () => {})

    await act(async () => {
      await view.result.current.transition({ ...runRecord('awaiting_approval', 8), instanceId: other }, 'apply')
    })
    expect(refreshContext).not.toHaveBeenCalled()
  })
})
