import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import { resetClientForTests } from '@/client'
import { jsonResponse, makeFakeFetch } from '@/client/http/__tests__/helpers'
import { useSessionStore } from '@/state'

import { RecoveryRestorePanel } from '../RecoveryRestorePanel'

const digest = (character: string) => `sha256:${character.repeat(64)}`
const backup = {
  receiptId: 'backup-0123456789abcdef01234567',
  receiptDigest: digest('1'),
  createdAt: '2026-08-01T10:00:00Z',
  archiveDigest: digest('2'),
  archiveFileDigest: digest('3'),
  manifestDigest: digest('4'),
  sourceLockDigest: digest('5'),
  fileCount: 7,
  storageLocation: 'stateport_managed_backup_root',
}
const plan = {
  formatVersion: 'stateport.restore-plan/v1',
  operation: 'restore_new_instance',
  sourceInstanceId: 'source-one',
  destinationInstanceId: 'source-one-restored',
  destinationName: 'Source one restored',
  identityPolicy: 'reidentify',
  backup,
  preconditions: {
    sourceBindingDigest: digest('6'),
    destinationRootClass: 'stateport_managed_instances_root',
    destinationAbsent: true,
    destinationCatalogIdentityAbsent: true,
  },
  dryRun: { status: 'verified', instanceId: 'source-one-restored', fileCount: 7, archiveDigest: digest('2') },
  effects: {
    sourceCanonicalState: 'unchanged',
    destinationCanonicalState: 'new_instance_created',
    externalEffectsRestored: false,
    overwriteAllowed: false,
    sourceAccess: { disposition: 'not_propagated' },
  },
  limitations: ['filesystem_state_only', 'external_side_effects_not_restored', 'source_instance_not_modified'],
  createdAt: '2026-08-01T10:01:00Z',
  expiresAt: '2026-08-01T10:16:00Z',
  planDigest: digest('7'),
}
const approval = {
  formatVersion: 'stateport.restore-approval/v1',
  operation: 'restore_new_instance',
  sourceInstanceId: 'source-one',
  destinationInstanceId: 'source-one-restored',
  planDigest: digest('7'),
  actor: { actorId: 'platform-operator', actorRole: 'platform_operator' },
  decision: 'approved',
  approvedAt: '2026-08-01T10:02:00Z',
  expiresAt: '2026-08-01T10:12:00Z',
  approvalDigest: digest('8'),
}
const receipt = {
  formatVersion: 'stateport.restore-receipt/v1',
  receiptId: 'restore-0123456789abcdef01234567',
  operation: 'restore_new_instance',
  status: 'validated',
  sourceInstanceId: 'source-one',
  destinationInstanceId: 'source-one-restored',
  planDigest: digest('7'),
  approvalDigest: digest('8'),
  backup,
  result: {
    identityPolicy: 'reidentify',
    instanceId: 'source-one-restored',
    fileCount: 7,
    archiveDigest: digest('2'),
    baseGit: 'a'.repeat(40),
    validation: { valid: true, issues: [] },
    catalogIdentity: { instanceId: 'source-one-restored', pathState: 'present' },
  },
  effects: {
    sourceCanonicalState: 'unchanged',
    destinationCanonicalState: 'new_instance_created',
    externalEffectsRestored: false,
    sourceAccess: { disposition: 'not_propagated' },
  },
  createdAt: '2026-08-01T10:03:00Z',
  receiptDigest: digest('9'),
}
const status = {
  formatVersion: 'stateport.recovery-status/v1',
  sourceInstanceId: 'source-one',
  status: 'verified',
  latest: {
    instanceId: 'source-one',
    archiveDigest: digest('2'),
    archiveFileDigest: digest('3'),
    createdAt: '2026-08-01T10:00:00Z',
    validation: 'verified',
    backupReceipt: { receiptId: backup.receiptId },
    storageLocation: 'stateport_managed_backup_root',
  },
  operatorInspectionRequired: false,
  verification: { archive: 'confined_regular_file' },
  restore: {
    status: 'not_planned',
    latestPlanDigest: null,
    latestApprovalDigest: null,
    latestReceiptId: null,
    operatorInspectionRequired: false,
    stagingRetained: false,
  },
  limitations: { filesystemStateOnly: true, externalEffectsRestored: false, overwriteRestoreSupported: false },
}

beforeEach(() => {
  vi.stubEnv('VITE_STATEPORT_ADAPTER', 'http')
  resetClientForTests()
  useSessionStore.setState({
    serviceStatus: {
      state: 'connected',
      endpoint: 'http://127.0.0.1:8790',
      actor: {
        role: 'platform_operator',
        actorId: 'platform-operator',
        platformOperationsAllowed: true,
        statebenchInspectionAllowed: true,
      },
    },
    toasts: [],
  })
})

afterEach(() => {
  cleanup()
  resetClientForTests()
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

it('reviews an exact path-free restore plan before approval and apply', async () => {
  const fake = makeFakeFetch([
    ['GET', '/v1/instances/source-one/recovery', jsonResponse({ ok: true, result: status })],
    ['POST', '/v1/instances/source-one/recovery/restore/plan', jsonResponse({ ok: true, result: plan })],
    ['POST', '/v1/instances/source-one/recovery/restore/approve', jsonResponse({ ok: true, result: approval })],
    ['POST', '/v1/instances/source-one/recovery/restore/apply', jsonResponse({ ok: true, result: receipt })],
  ])
  vi.stubGlobal('fetch', fake.fetchFn)
  const onRestored = vi.fn()
  const user = userEvent.setup()
  render(<RecoveryRestorePanel instanceId="source-one" onRestored={onRestored} />)

  expect(await screen.findByText(backup.receiptId)).toBeTruthy()
  expect(screen.getByText('Not planned')).toBeTruthy()
  await user.click(screen.getByTestId('restore-plan-action'))
  expect(await screen.findByText(plan.planDigest)).toBeTruthy()
  expect(screen.getByText(/source unchanged; no external effects restored/i)).toBeTruthy()

  await user.click(screen.getByTestId('restore-approve-action'))
  expect(await screen.findByText(approval.approvalDigest)).toBeTruthy()
  await user.click(screen.getByTestId('restore-apply-action'))
  expect(await screen.findByText('Create the recovered instance?')).toBeTruthy()
  await user.click(screen.getByTestId('confirm-action'))

  expect(await screen.findByText(receipt.receiptId)).toBeTruthy()
  expect(screen.getByText(receipt.receiptDigest)).toBeTruthy()
  await waitFor(() => expect(onRestored).toHaveBeenCalledTimes(1))
  expect(fake.callsTo('/recovery/restore/plan')[0].body).toMatchObject({
    backupReceiptId: backup.receiptId,
    destinationInstanceId: 'source-one-restored',
  })
  expect(fake.callsTo('/recovery/restore/approve')[0].body).toEqual({ planDigest: plan.planDigest })
  expect(fake.callsTo('/recovery/restore/apply')[0].body).toEqual({
    planDigest: plan.planDigest,
    approvalDigest: approval.approvalDigest,
  })
})

it('shows the persisted restore status and receipt without a local apply', async () => {
  const persistedStatus = {
    ...status,
    restore: {
      ...status.restore,
      status: 'validated',
      latestPlanDigest: plan.planDigest,
      latestApprovalDigest: approval.approvalDigest,
      latestReceiptId: receipt.receiptId,
      destinationInstanceId: receipt.destinationInstanceId,
    },
  }
  const fake = makeFakeFetch([
    ['GET', '/v1/instances/source-one/recovery', jsonResponse({ ok: true, result: persistedStatus })],
  ])
  vi.stubGlobal('fetch', fake.fetchFn)
  render(<RecoveryRestorePanel instanceId="source-one" onRestored={vi.fn()} />)

  expect(await screen.findByText('Validated')).toBeTruthy()
  expect(screen.getByText(receipt.receiptId)).toBeTruthy()
})

it('reloads and exposes retained staging after a failed restore', async () => {
  let statusReads = 0
  const failedStatus = {
    ...status,
    restore: {
      status: 'failed',
      latestPlanDigest: plan.planDigest,
      latestApprovalDigest: approval.approvalDigest,
      latestReceiptId: null,
      operatorInspectionRequired: true,
      stagingRetained: true,
      destinationInstanceId: plan.destinationInstanceId,
      failureReasonCode: 'restore_apply_failed',
    },
  }
  const fake = makeFakeFetch([
    [
      'GET',
      '/v1/instances/source-one/recovery',
      () =>
        jsonResponse({
          ok: true,
          result: statusReads++ === 0 ? status : failedStatus,
        }),
    ],
    ['POST', '/v1/instances/source-one/recovery/restore/plan', jsonResponse({ ok: true, result: plan })],
    ['POST', '/v1/instances/source-one/recovery/restore/approve', jsonResponse({ ok: true, result: approval })],
    [
      'POST',
      '/v1/instances/source-one/recovery/restore/apply',
      jsonResponse(
        {
          ok: false,
          error: { code: 'restore_failed', message: 'Restore transaction failed.' },
        },
        500,
      ),
    ],
  ])
  vi.stubGlobal('fetch', fake.fetchFn)
  const user = userEvent.setup()
  render(<RecoveryRestorePanel instanceId="source-one" onRestored={vi.fn()} />)

  expect(await screen.findByText(backup.receiptId)).toBeTruthy()
  await user.click(screen.getByTestId('restore-plan-action'))
  await user.click(await screen.findByTestId('restore-approve-action'))
  await user.click(await screen.findByTestId('restore-apply-action'))
  await user.click(await screen.findByTestId('confirm-action'))

  expect(await screen.findByText('Restore needs operator inspection')).toBeTruthy()
  expect(screen.getByText(/retained bounded staging data/i)).toBeTruthy()
  expect(
    fake.calls.filter(
      (call) =>
        call.method === 'GET' &&
        new URL(call.url, 'http://stateport.test').pathname ===
          '/v1/instances/source-one/recovery',
    ),
  ).toHaveLength(2)
})

it('clears stale restore truth when post-failure status cannot be reloaded', async () => {
  let statusReads = 0
  const approvedStatus = {
    ...status,
    restore: {
      ...status.restore,
      status: 'approved',
      latestPlanDigest: plan.planDigest,
      latestApprovalDigest: approval.approvalDigest,
      destinationInstanceId: plan.destinationInstanceId,
    },
  }
  const fake = makeFakeFetch([
    [
      'GET',
      '/v1/instances/source-one/recovery',
      () =>
        statusReads++ === 0
          ? jsonResponse({ ok: true, result: approvedStatus })
          : jsonResponse(
              { ok: false, error: { code: 'recovery_unavailable', message: 'Status unavailable.' } },
              500,
            ),
    ],
    ['POST', '/v1/instances/source-one/recovery/restore/plan', jsonResponse({ ok: true, result: plan })],
    ['POST', '/v1/instances/source-one/recovery/restore/approve', jsonResponse({ ok: true, result: approval })],
    [
      'POST',
      '/v1/instances/source-one/recovery/restore/apply',
      jsonResponse(
        { ok: false, error: { code: 'restore_failed', message: 'Restore transaction failed.' } },
        500,
      ),
    ],
  ])
  vi.stubGlobal('fetch', fake.fetchFn)
  const user = userEvent.setup()
  render(<RecoveryRestorePanel instanceId="source-one" onRestored={vi.fn()} />)

  expect(await screen.findByText('Approved')).toBeTruthy()
  await user.click(screen.getByTestId('restore-plan-action'))
  await user.click(await screen.findByTestId('restore-approve-action'))
  await user.click(await screen.findByTestId('restore-apply-action'))
  await user.click(await screen.findByTestId('confirm-action'))

  expect(await screen.findByText('Unavailable')).toBeTruthy()
  expect(screen.queryByText('Approved')).toBeNull()
  expect(screen.getByText('Restore transaction failed.')).toBeTruthy()
})


it('isolates delayed recovery status and destination drafts when switching instances', async () => {
  let completeOld!: (response: Response) => void
  const oldResponse = new Promise<Response>((resolve) => { completeOld = resolve })
  const secondStatus = { ...status, sourceInstanceId: 'source-two', latest: { ...status.latest,
    instanceId: 'source-two', backupReceipt: { receiptId: 'backup-aaaaaaaaaaaaaaaaaaaaaaaa' } } }
  const fake = makeFakeFetch([
    ['GET', '/v1/instances/source-one/recovery', () => oldResponse],
    ['GET', '/v1/instances/source-two/recovery', jsonResponse({ ok: true, result: secondStatus })],
  ])
  vi.stubGlobal('fetch', fake.fetchFn)
  const user = userEvent.setup()
  const view = render(<RecoveryRestorePanel instanceId="source-one" onRestored={vi.fn()} />)
  await user.clear(screen.getByTestId('restore-destination-id'))
  await user.type(screen.getByTestId('restore-destination-id'), 'old-destination')
  view.rerender(<RecoveryRestorePanel instanceId="source-two" onRestored={vi.fn()} />)
  expect(await screen.findByText(secondStatus.latest.backupReceipt.receiptId)).toBeTruthy()
  await act(async () => { completeOld(jsonResponse({ ok: true, result: status })); await oldResponse })
  expect(screen.queryByText(backup.receiptId)).toBeNull()
  expect((screen.getByTestId('restore-destination-id') as HTMLInputElement).value).toBe('source-two-restored')
})

it('does not carry a reviewed approval or confirmation dialog to another instance', async () => {
  const secondStatus = { ...status, sourceInstanceId: 'source-two', latest: { ...status.latest, instanceId: 'source-two' } }
  const fake = makeFakeFetch([
    ['GET', '/v1/instances/source-one/recovery', jsonResponse({ ok: true, result: status })],
    ['GET', '/v1/instances/source-two/recovery', jsonResponse({ ok: true, result: secondStatus })],
    ['POST', '/v1/instances/source-one/recovery/restore/plan', jsonResponse({ ok: true, result: plan })],
    ['POST', '/v1/instances/source-one/recovery/restore/approve', jsonResponse({ ok: true, result: approval })],
  ])
  vi.stubGlobal('fetch', fake.fetchFn)
  const user = userEvent.setup()
  const view = render(<RecoveryRestorePanel instanceId="source-one" onRestored={vi.fn()} />)
  await screen.findByText(backup.receiptId)
  await user.click(screen.getByTestId('restore-plan-action'))
  await user.click(await screen.findByTestId('restore-approve-action'))
  await user.click(await screen.findByTestId('restore-apply-action'))
  expect(await screen.findByTestId('confirm-action')).toBeTruthy()
  view.rerender(<RecoveryRestorePanel instanceId="source-two" onRestored={vi.fn()} />)
  await waitFor(() => expect(screen.queryByTestId('confirm-action')).toBeNull())
  expect(screen.queryByText(plan.planDigest)).toBeNull()
  expect(screen.queryByText(approval.approvalDigest)).toBeNull()
  expect(fake.callsTo('/recovery/restore/apply')).toHaveLength(0)
})

it('does not notify the new instance when an earlier apply completes after navigation', async () => {
  let completeApply!: (response: Response) => void
  const delayed = new Promise<Response>((resolve) => { completeApply = resolve })
  const secondStatus = { ...status, sourceInstanceId: 'source-two', latest: { ...status.latest, instanceId: 'source-two' } }
  const fake = makeFakeFetch([
    ['GET', '/v1/instances/source-one/recovery', jsonResponse({ ok: true, result: status })],
    ['GET', '/v1/instances/source-two/recovery', jsonResponse({ ok: true, result: secondStatus })],
    ['POST', '/v1/instances/source-one/recovery/restore/plan', jsonResponse({ ok: true, result: plan })],
    ['POST', '/v1/instances/source-one/recovery/restore/approve', jsonResponse({ ok: true, result: approval })],
    ['POST', '/v1/instances/source-one/recovery/restore/apply', () => delayed],
  ])
  vi.stubGlobal('fetch', fake.fetchFn)
  const user = userEvent.setup()
  const onRestored = vi.fn()
  const view = render(<RecoveryRestorePanel instanceId="source-one" onRestored={onRestored} />)
  await screen.findByText(backup.receiptId)
  await user.click(screen.getByTestId('restore-plan-action'))
  await user.click(await screen.findByTestId('restore-approve-action'))
  await user.click(await screen.findByTestId('restore-apply-action'))
  await user.click(await screen.findByTestId('confirm-action'))
  await waitFor(() => expect(fake.callsTo('/recovery/restore/apply')).toHaveLength(1))
  view.rerender(<RecoveryRestorePanel instanceId="source-two" onRestored={onRestored} />)
  await act(async () => { completeApply(jsonResponse({ ok: true, result: receipt })); await delayed })
  expect(onRestored).not.toHaveBeenCalled()
  expect(useSessionStore.getState().toasts).toEqual([])
  expect(screen.queryByText(receipt.receiptId)).toBeNull()
})
