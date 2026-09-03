import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ApplicationInstance, GovernedAction, RunOperation, RunRecord, StudyStatePackageData } from '@/client'
import { getClient, resetClientForTests } from '@/client'
import { useApplicationsPrefs } from '@/features/applications/lib/prefsStore'

import { StudyJourney } from '../components/StudyJourney'

const BEFORE = `sha256:${'a'.repeat(64)}`
const AFTER = `sha256:${'b'.repeat(64)}`

const study: StudyStatePackageData = {
  kind: 'study-state',
  goal: 'Learn the governed evidence loop',
  goalProgressPercent: 0,
  planDigest: BEFORE,
  canUndo: false,
  activities: [
    {
      id: 'evidence-practice',
      title: 'Complete one evidence-backed practice activity',
      reason: 'This is the next unfinished activity.',
      state: 'not_started',
      updatedAt: '2026-07-28T12:00:00Z',
    },
    {
      id: 'explain-back',
      title: 'Explain the governance loop',
      reason: 'Use this when writing is a better fit.',
      state: 'not_started',
      updatedAt: '2026-07-28T12:00:00Z',
    },
  ],
  evidence: [],
}

const instance = {
  id: 'study-browser',
  name: 'StudyState Sample',
  packageId: 'studystate.sample',
  packageName: 'studystate.sample',
  packageDisplayName: 'StudyState Sample',
  health: 'ready',
  attention: [],
  recentActivity: [],
  settings: {
    instanceId: 'study-browser',
    notificationLevel: 'inherit',
    conversation: { defaultContext: ['application'] },
    backup: { enabled: false, intervalHours: 24 },
    terminal: {},
  },
  capabilities: [{ id: 'goal_execution', status: 'available' }],
  receiptIds: [],
  recovery: { state: 'not_configured' },
  packageState: study,
  pinned: false,
  createdAt: '2026-07-28T12:00:00Z',
} as ApplicationInstance

function action(id: string, title: string): GovernedAction {
  return { id, instanceId: instance.id, title, engineIds: [] }
}

const allActions = [
  action('studystate.sample.record-evidence/v1', 'Record evidence'),
  action('studystate.sample.start-activity/v1', 'Start activity'),
  action('studystate.sample.pause-activity/v1', 'Pause activity'),
  action('studystate.sample.redirect-activity/v1', 'Redirect activity'),
  action('studystate.sample.undo-last-evidence/v1', 'Undo evidence'),
]

function record(
  revision: number,
  status: RunRecord['status'],
  options: {
    actionId?: string
    proposal?: Record<string, unknown>
    withReceipt?: boolean
  } = {},
): RunRecord {
  const actionId = options.actionId ?? 'studystate.sample.record-evidence/v1'
  const receiptId = 'receipt-study-control-1'
  return {
    id: 'run-study-1',
    instanceId: instance.id,
    actionId,
    engineId: 'synthetic',
    state: status === 'applied' ? 'completed' : 'awaiting_approval',
    status,
    revision,
    inputs: {},
    proposalDigest: options.proposal ? { algorithm: 'sha256', value: AFTER } : undefined,
    proposal: options.proposal ? { operation: options.proposal } : undefined,
    receiptId: options.withReceipt ? receiptId : undefined,
    closureReceipt: options.withReceipt ? {
      receiptId,
      runId: 'run-study-1',
      instanceId: instance.id,
      status: 'applied',
      validation: { state: 'validated' },
    } : undefined,
    createdAt: '2026-07-28T12:00:00Z',
    updatedAt: '2026-07-28T12:00:00Z',
  }
}

function recordOperation(activityTitle: string, reflection: string): Record<string, unknown> {
  return {
    type: 'record_evidence',
    path: 'state/LEARNING.yaml',
    activityId: 'evidence-practice',
    activityTitle,
    summary: reflection,
    reflection,
    priorStatus: 'planned',
    beforePlanDigest: BEFORE,
    afterPlanDigest: AFTER,
  }
}

function mockLifecycle(
  actionId: string,
  proposal: Record<string, unknown>,
  options: { applyError?: Error; withReceipt?: boolean } = {},
) {
  const runs = getClient().runs
  vi.spyOn(runs, 'listActions').mockResolvedValue(allActions)
  vi.spyOn(runs, 'listEngines').mockResolvedValue([
    { id: 'synthetic', label: 'Local', kind: 'synthetic', availability: 'available', available: true },
  ])
  vi.spyOn(runs, 'prepare').mockResolvedValue(record(1, 'awaiting_approval', { actionId }))
  const transition = vi.spyOn(runs, 'transition').mockImplementation(
    async (_id, operation: RunOperation) => {
      if (operation === 'approve') return record(2, 'approved', { actionId })
      if (operation === 'execute') return record(3, 'state_change_proposed', { actionId, proposal })
      if (operation === 'proposal-approve') return record(4, 'state_change_approved', { actionId, proposal })
      if (options.applyError) throw options.applyError
      return record(5, 'applied', { actionId, proposal, withReceipt: options.withReceipt })
    },
  )
  return { runs, transition }
}

beforeEach(() => {
  resetClientForTests()
  useApplicationsPrefs.setState({ studyReflectionDrafts: {} })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  resetClientForTests()
  useApplicationsPrefs.setState({ studyReflectionDrafts: {} })
})

describe('StudyState focused learning journey', () => {
  it('keeps durable controls and browser-local reflection drafts visibly separate', async () => {
    const user = userEvent.setup()
    vi.spyOn(getClient().runs, 'listActions').mockResolvedValue(allActions)

    render(<StudyJourney instance={instance} study={study} onDurableStateChanged={() => undefined} />)

    expect(await screen.findByRole('heading', {
      level: 2,
      name: 'Complete one evidence-backed practice activity',
    })).toBeTruthy()
    expect(screen.getByTestId('study-durable-status').textContent).toBe('Durable state · Not started')
    const start = screen.getByRole('button', { name: 'Start activity' })
    expect(start.getAttribute('data-variant')).toBe('default')
    expect(screen.getByText(/Start, Pause, and Redirect change durable learning state only after exact review/)).toBeTruthy()

    await user.click(screen.getByRole('button', { name: 'Write reflection' }))
    const reflection = screen.getByLabelText(/What changed in your understanding/) as HTMLTextAreaElement
    expect(document.activeElement).toBe(reflection)
    await user.type(reflection, 'A draft remains local until a separate evidence approval.')
    expect(useApplicationsPrefs.getState().studyReflectionDrafts[`${instance.id}:evidence-practice`]).toBe(
      'A draft remains local until a separate evidence approval.',
    )
    expect(screen.getByText(/stored in this browser only/)).toBeTruthy()
  })

  it('reviews and applies Start with exact digest inputs and a validated closure receipt', async () => {
    const user = userEvent.setup()
    const proposal = {
      type: 'start_activity',
      activityId: 'evidence-practice',
      activityTitle: 'Complete one evidence-backed practice activity',
      priorStatus: 'planned',
      resultingStatus: 'in_progress',
      expectedPlanDigest: BEFORE,
      resultingPlanDigest: AFTER,
    }
    const { runs, transition } = mockLifecycle('studystate.sample.start-activity/v1', proposal, { withReceipt: true })
    const refreshed = vi.fn()

    render(<StudyJourney instance={instance} study={study} onDurableStateChanged={refreshed} />)
    await user.click(await screen.findByRole('button', { name: 'Start activity' }))

    expect(await screen.findByRole('heading', { level: 3, name: 'Review Start' })).toBeTruthy()
    expect(screen.getByTestId('study-review-activity').textContent).toBe('Complete one evidence-backed practice activity')
    expect(screen.getByTestId('study-review-result').textContent).toBe('Not started → In progress')
    expect(runs.prepare).toHaveBeenCalledWith(instance.id, {
      actionId: 'studystate.sample.start-activity/v1',
      engineId: 'synthetic',
      inputs: { activityId: 'evidence-practice', expectedPlanDigest: BEFORE },
    })
    expect(transition.mock.calls.map((call) => call[1])).toEqual(['approve', 'execute'])

    await user.click(screen.getByRole('button', { name: 'Approve Start' }))
    await waitFor(() => expect(refreshed).toHaveBeenCalledTimes(1))
    expect(transition.mock.calls.map((call) => call[1])).toEqual([
      'approve', 'execute', 'proposal-approve', 'apply',
    ])
    expect(await screen.findByText('Activity started in durable learning state')).toBeTruthy()
    expect(screen.getByText(/validated closure receipt and re-read the durable instance state/)).toBeTruthy()
    expect(screen.getByTestId('study-control-receipt').textContent).toContain('receipt-study-control-1')
  })

  it('derives Pause from the sole active activity and shows the exact durable transition', async () => {
    const user = userEvent.setup()
    const activeStudy: StudyStatePackageData = {
      ...study,
      activities: [
        { ...study.activities[0], state: 'in_progress' },
        study.activities[1],
      ],
    }
    const proposal = {
      type: 'pause_activity',
      activityId: 'evidence-practice',
      activityTitle: 'Complete one evidence-backed practice activity',
      priorStatus: 'in_progress',
      resultingStatus: 'paused',
      expectedPlanDigest: BEFORE,
      resultingPlanDigest: AFTER,
    }
    const { runs } = mockLifecycle('studystate.sample.pause-activity/v1', proposal, { withReceipt: true })

    render(<StudyJourney instance={instance} study={activeStudy} onDurableStateChanged={() => undefined} />)
    expect((await screen.findByTestId('study-durable-status')).textContent).toBe('Durable state · In progress')
    await user.click(screen.getByRole('button', { name: 'Pause activity' }))

    expect(await screen.findByRole('heading', { level: 3, name: 'Review Pause' })).toBeTruthy()
    expect(screen.getByTestId('study-review-result').textContent).toBe('In progress → Paused')
    expect(runs.prepare).toHaveBeenCalledWith(instance.id, {
      actionId: 'studystate.sample.pause-activity/v1',
      engineId: 'synthetic',
      inputs: { activityId: 'evidence-practice', expectedPlanDigest: BEFORE },
    })
  })

  it('reveals Redirect targets progressively and reviews the exact atomic source and target', async () => {
    const user = userEvent.setup()
    const activeStudy: StudyStatePackageData = {
      ...study,
      activities: [
        { ...study.activities[0], state: 'in_progress' },
        study.activities[1],
      ],
    }
    const proposal = {
      type: 'redirect_activity',
      fromActivityId: 'evidence-practice',
      fromActivityTitle: 'Complete one evidence-backed practice activity',
      fromPriorStatus: 'in_progress',
      fromResultingStatus: 'paused',
      toActivityId: 'explain-back',
      toActivityTitle: 'Explain the governance loop',
      toPriorStatus: 'planned',
      toResultingStatus: 'in_progress',
      expectedPlanDigest: BEFORE,
      resultingPlanDigest: AFTER,
    }
    const { runs } = mockLifecycle('studystate.sample.redirect-activity/v1', proposal, { withReceipt: true })

    render(<StudyJourney instance={instance} study={activeStudy} onDurableStateChanged={() => undefined} />)
    expect(screen.queryByTestId('study-redirect-options')).toBeNull()
    await user.click(await screen.findByRole('button', { name: 'Choose another activity' }))
    const target = screen.getByTestId('study-redirect-target-explain-back')
    expect(document.activeElement).toBe(target)
    await user.click(target)
    expect(target.getAttribute('aria-pressed')).toBe('true')
    await user.click(screen.getByRole('button', { name: 'Review redirect' }))

    expect(await screen.findByRole('heading', { level: 3, name: 'Review Redirect' })).toBeTruthy()
    expect(screen.getByTestId('study-review-activity').textContent).toBe('Complete one evidence-backed practice activity')
    expect(screen.getByTestId('study-review-target').textContent).toBe('Explain the governance loop')
    expect(screen.getByTestId('study-human-readable-changes').textContent).toContain('Apply both changes atomically')
    expect(runs.prepare).toHaveBeenCalledWith(instance.id, {
      actionId: 'studystate.sample.redirect-activity/v1',
      engineId: 'synthetic',
      inputs: {
        fromActivityId: 'evidence-practice',
        toActivityId: 'explain-back',
        expectedPlanDigest: BEFORE,
      },
    })
  })

  it('fails closed on malformed or stale durable transition proposals', async () => {
    const user = userEvent.setup()
    const malformed = {
      type: 'start_activity',
      activityId: 'evidence-practice',
      priorStatus: 'planned',
      resultingStatus: 'in_progress',
      expectedPlanDigest: BEFORE,
      resultingPlanDigest: AFTER,
    }
    mockLifecycle('studystate.sample.start-activity/v1', malformed)

    const rendered = render(<StudyJourney instance={instance} study={study} onDurableStateChanged={() => undefined} />)
    await user.click(await screen.findByRole('button', { name: 'Start activity' }))
    expect(await screen.findByText(/did not bind activityTitle/)).toBeTruthy()
    expect(screen.queryByTestId('study-change-preview')).toBeNull()
    rendered.unmount()

    vi.restoreAllMocks()
    const runs = getClient().runs
    vi.spyOn(runs, 'listActions').mockResolvedValue(allActions)
    vi.spyOn(runs, 'listEngines').mockResolvedValue([
      { id: 'synthetic', label: 'Local', kind: 'synthetic', availability: 'available', available: true },
    ])
    vi.spyOn(runs, 'prepare').mockRejectedValue(new Error('expectedPlanDigest must match the current durable plan'))
    render(<StudyJourney instance={instance} study={study} onDurableStateChanged={() => undefined} />)
    await user.click(await screen.findByRole('button', { name: 'Start activity' }))
    expect(await screen.findByText('The learning state was not changed')).toBeTruthy()
    expect(screen.getByText(/expectedPlanDigest must match the current durable plan/)).toBeTruthy()
  })

  it('reviews exact reflection evidence separately from durable activity controls', async () => {
    const user = userEvent.setup()
    const reflection = 'Approval separates evidence from application state.'
    const proposal = recordOperation('Complete one evidence-backed practice activity', reflection)
    const { runs, transition } = mockLifecycle('studystate.sample.record-evidence/v1', proposal)
    const refreshed = vi.fn()

    render(<StudyJourney instance={instance} study={study} onDurableStateChanged={refreshed} />)
    await user.click(await screen.findByRole('button', { name: 'Write reflection' }))
    await user.type(screen.getByLabelText(/What changed in your understanding/), reflection)
    await user.click(screen.getByTestId('study-review-change'))

    const preview = await screen.findByTestId('study-change-preview')
    expect(screen.getByTestId('study-review-activity').textContent).toBe('Complete one evidence-backed practice activity')
    expect(screen.getByTestId('study-review-reflection').textContent).toBe(reflection)
    expect(preview.textContent).toContain('Self-reported · not assessed')
    expect(preview.textContent).toContain('it will not be labelled verified')
    expect(runs.prepare).toHaveBeenCalledWith(instance.id, {
      actionId: 'studystate.sample.record-evidence/v1',
      engineId: 'synthetic',
      inputs: { activityId: 'evidence-practice', evidenceSummary: reflection },
    })

    await user.click(screen.getByTestId('study-approve-apply'))
    await waitFor(() => expect(refreshed).toHaveBeenCalledTimes(1))
    expect(transition.mock.calls.map((call) => call[1])).toEqual([
      'approve', 'execute', 'proposal-approve', 'apply',
    ])
    expect(await screen.findByText(/Self-reported reflection saved to durable learning state/)).toBeTruthy()
    expect(useApplicationsPrefs.getState().studyReflectionDrafts[`${instance.id}:evidence-practice`]).toBeUndefined()
  })

  it('shows exact digest-bound Undo without touching browser drafts', async () => {
    const user = userEvent.setup()
    const durable: StudyStatePackageData = {
      ...study,
      planDigest: AFTER,
      canUndo: true,
      goalProgressPercent: 50,
      activities: [{ ...study.activities[0], state: 'done' }, study.activities[1]],
      evidence: [{ id: 'evidence-1', title: 'Recorded reflection', state: 'self_reported', updatedAt: '2026-07-28T12:01:00Z' }],
      lastTransition: { kind: 'evidence_applied', beforePlanDigest: BEFORE, afterPlanDigest: AFTER },
    }
    const undoOperation = {
      type: 'undo_last_evidence',
      activityId: 'evidence-practice',
      activityTitle: 'Complete one evidence-backed practice activity',
      evidenceId: 'evidence-1',
      reflection: 'Recorded reflection',
      restoreStatus: 'planned',
      expectedCurrentPlanDigest: AFTER,
      restoredPlanDigest: BEFORE,
    }
    useApplicationsPrefs.setState({
      studyReflectionDrafts: { [`${instance.id}:explain-back`]: 'Keep this separate browser draft.' },
    })
    const { runs } = mockLifecycle('studystate.sample.undo-last-evidence/v1', undoOperation)

    render(<StudyJourney instance={instance} study={durable} onDurableStateChanged={() => undefined} />)
    await user.click(await screen.findByTestId('study-undo'))

    const preview = await screen.findByTestId('study-change-preview')
    expect(screen.getByTestId('study-review-activity').textContent).toBe('Complete one evidence-backed practice activity')
    expect(screen.getByTestId('study-review-reflection').textContent).toBe('Recorded reflection')
    expect(preview.textContent).toContain('from completed to not started')
    expect(preview.textContent).toContain('Keep all browser-local drafts unchanged')
    expect(runs.prepare).toHaveBeenCalledWith(instance.id, {
      actionId: 'studystate.sample.undo-last-evidence/v1',
      engineId: 'synthetic',
      inputs: { expectedPlanDigest: AFTER },
    })
    expect(useApplicationsPrefs.getState().studyReflectionDrafts[`${instance.id}:explain-back`]).toBe(
      'Keep this separate browser draft.',
    )
  })

  it('keeps the browser draft when a durable apply outcome is unknown', async () => {
    const user = userEvent.setup()
    const reflection = 'Preserve me until apply is confirmed.'
    const proposal = recordOperation('Complete one evidence-backed practice activity', reflection)
    mockLifecycle('studystate.sample.record-evidence/v1', proposal, { applyError: new Error('connection lost') })

    render(<StudyJourney instance={instance} study={study} onDurableStateChanged={() => undefined} />)
    await user.click(await screen.findByRole('button', { name: 'Write reflection' }))
    await user.type(screen.getByLabelText(/What changed in your understanding/), reflection)
    await user.click(screen.getByTestId('study-review-change'))
    await user.click(await screen.findByTestId('study-approve-apply'))

    expect(await screen.findByText('Apply outcome needs verification')).toBeTruthy()
    expect(useApplicationsPrefs.getState().studyReflectionDrafts[`${instance.id}:evidence-practice`]).toBe(reflection)
  })
})
