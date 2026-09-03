/**
 * Recovery HTTP contract: the backup mutation returns its receipt under the
 * backend-owned `backupReceipt` field. The client must validate that nested
 * receipt before reporting success. A secondary projection refresh must never
 * turn a completed mutation into an ambiguous failure/retry invitation.
 */
import { describe, expect, it, vi } from 'vitest'

import type { ApplicationsClient } from '../../client'
import { ClientError, type ApplicationInstance } from '../../types'
import { HttpRecoveryClient } from '../domainsCore'
import { mapInstance } from '../mappers'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const recovery: ApplicationInstance['recovery'] = {
  state: 'current',
  lastBackupAt: '2026-07-19T00:00:00Z',
  detail: 'Latest backup is verified.',
}

function applications(): ApplicationsClient {
  return {
    get: vi.fn().mockResolvedValue({ recovery }),
  } as unknown as ApplicationsClient
}

function backupPayload(instanceId = 'ins_1') {
  return {
    instanceId,
    archive: `/backups/${instanceId}/20260719T000000Z.tar`,
    archiveDigest: `sha256:${'a'.repeat(64)}`,
    archiveFileDigest: `sha256:${'b'.repeat(64)}`,
    createdAt: '2026-07-19T00:00:00Z',
    validation: 'verified',
    backupReceipt: {
      formatVersion: 'stateport.backup-receipt/v1',
      receiptId: 'backup-0123456789abcdef01234567',
      action: 'backup.create',
      status: 'verified',
      instanceId,
      archiveDigest: `sha256:${'a'.repeat(64)}`,
      archiveFileDigest: `sha256:${'b'.repeat(64)}`,
      canonicalStateEffect: 'none',
      createdAt: '2026-07-19T00:00:00Z',
    },
  }
}

describe('HttpRecoveryClient', () => {
  it('maps the nested backup receipt and refreshes recovery state', async () => {
    const fake = makeFakeFetch([
      [
        'POST',
        '/v1/instances/ins_1/backup',
        jsonResponse({ ok: true, result: backupPayload() }),
      ],
    ])
    const appClient = applications()
    const client = new HttpRecoveryClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
      appClient,
    )

    const result = await client.runBackup('ins_1')

    expect(fake.callsTo('/v1/instances/ins_1/backup')[0]).toMatchObject({
      method: 'POST',
      body: {},
      headers: { 'x-stateport-csrf': 'test-csrf' },
    })
    expect(appClient.get).not.toHaveBeenCalled()
    expect(result.recovery).toEqual({
      state: 'current',
      lastBackupAt: '2026-07-19T00:00:00Z',
      lastReceiptId: 'backup-0123456789abcdef01234567',
      detail: 'The backup receipt records local validation.',
    })
    expect(result.receipt).toMatchObject({
      id: 'backup-0123456789abcdef01234567',
      instanceId: 'ins_1',
      actionName: 'Backup created',
      result: 'validated',
      validation: { state: 'validated' },
    })
  })

  it('preserves a validated backup result when the application projection is unavailable', async () => {
    const fake = makeFakeFetch([
      [
        'POST',
        '/v1/instances/ins_1/backup',
        jsonResponse({ ok: true, result: backupPayload() }),
      ],
    ])
    const appClient = applications()
    vi.mocked(appClient.get).mockRejectedValue(
      new ClientError('network', 'projection refresh failed'),
    )
    const client = new HttpRecoveryClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
      appClient,
    )

    await expect(client.runBackup('ins_1')).resolves.toMatchObject({
      receipt: {
        id: 'backup-0123456789abcdef01234567',
        result: 'validated',
      },
      recovery: {
        state: 'current',
        lastReceiptId: 'backup-0123456789abcdef01234567',
      },
    })
    expect(appClient.get).not.toHaveBeenCalled()
  })

  it('maps verified and degraded backend recovery states honestly', () => {
    const base = {
      instanceId: 'ins_1',
      applicationId: 'projectstate',
      health: 'valid',
    }
    const verified = mapInstance({
      ...base,
      recovery: {
        status: 'verified',
        latest: {
          createdAt: '2026-07-19T00:00:00Z',
          backupReceipt: {
            receiptId: 'backup-0123456789abcdef01234567',
          },
        },
        operatorInspectionRequired: false,
      },
    })
    const degraded = mapInstance({
      ...base,
      recovery: {
        status: 'degraded',
        latest: {
          createdAt: '2026-07-19T00:00:00Z',
          backupReceipt: {
            receiptId: 'backup-fedcba9876543210fedcba98',
          },
        },
        operatorInspectionRequired: true,
        verificationIssues: ['The recorded archive is missing.'],
      },
    })

    expect(verified.recovery).toMatchObject({
      state: 'current',
      lastBackupAt: '2026-07-19T00:00:00Z',
      lastReceiptId: 'backup-0123456789abcdef01234567',
    })
    expect(degraded.recovery).toMatchObject({
      state: 'failed',
      lastReceiptId: 'backup-fedcba9876543210fedcba98',
      detail: 'The recorded archive is missing.',
    })
  })

  it('fails closed when the backup receipt belongs to another instance', async () => {
    const fake = makeFakeFetch([
      [
        'POST',
        '/v1/instances/ins_1/backup',
        jsonResponse({ ok: true, result: backupPayload('ins_other') }),
      ],
    ])
    const appClient = applications()
    const client = new HttpRecoveryClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
      appClient,
    )

    const error = await client.runBackup('ins_1').catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
    expect(appClient.get).not.toHaveBeenCalled()
  })

  it('validates and sends the governed restore status, plan, approval, and apply contracts', async () => {
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
      storageLocation: 'stateport_managed_backup_root' as const,
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
      dryRun: {
        status: 'verified',
        instanceId: 'source-one-restored',
        fileCount: 7,
        archiveDigest: digest('2'),
      },
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
      limitations: {
        filesystemStateOnly: true,
        externalEffectsRestored: false,
        overwriteRestoreSupported: false,
      },
    }
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/source-one/recovery', jsonResponse({ ok: true, result: status })],
      ['POST', '/v1/instances/source-one/recovery/restore/plan', jsonResponse({ ok: true, result: plan })],
      ['POST', '/v1/instances/source-one/recovery/restore/approve', jsonResponse({ ok: true, result: approval })],
      ['POST', '/v1/instances/source-one/recovery/restore/apply', jsonResponse({ ok: true, result: receipt })],
    ])
    const client = new HttpRecoveryClient(new HttpTransport({ fetchFn: fake.fetchFn }), applications())

    await expect(client.getStatus('source-one')).resolves.toEqual(status)
    await expect(
      client.planRestore('source-one', {
        backupReceiptId: backup.receiptId,
        destinationInstanceId: 'source-one-restored',
        destinationName: 'Source one restored',
      }),
    ).resolves.toEqual(plan)
    await expect(client.approveRestore('source-one', plan.planDigest)).resolves.toEqual(approval)
    await expect(
      client.applyRestore('source-one', {
        planDigest: plan.planDigest,
        approvalDigest: approval.approvalDigest,
      }),
    ).resolves.toEqual(receipt)

    expect(fake.callsTo('/recovery/restore/plan')[0].body).toEqual({
      backupReceiptId: backup.receiptId,
      destinationInstanceId: 'source-one-restored',
      destinationName: 'Source one restored',
    })
    expect(fake.callsTo('/recovery/restore/approve')[0].body).toEqual({ planDigest: plan.planDigest })
    expect(fake.callsTo('/recovery/restore/apply')[0].body).toEqual({
      planDigest: plan.planDigest,
      approvalDigest: approval.approvalDigest,
    })
  })
})
