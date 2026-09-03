import { useCallback, useEffect, useState } from 'react'

import type { RecoveryStatus, RestoreApproval, RestorePlan, RestoreReceipt } from '@/client'
import { getClient } from '@/client'
import { ConfirmDialog, InlineNotice } from '@/components'
import { Button } from '@/components/ui/button'
import { useSessionStore } from '@/state'

import { ReadOnlyValue, SettingRow, SettingSubsection } from './controls'

const INSTANCE_ID = /^[a-z][a-z0-9-]{1,63}$/
const RESTORE_STATUS_LABEL: Record<RecoveryStatus['restore']['status'], string> = {
  not_planned: 'Not planned',
  planned: 'Planned',
  approved: 'Approved',
  validated: 'Validated',
  failed: 'Failed',
}

export function RecoveryRestorePanel({
  instanceId,
  onRestored,
}: {
  instanceId: string
  onRestored: () => void
}) {
  const serviceStatus = useSessionStore((state) => state.serviceStatus)
  const pushToast = useSessionStore((state) => state.pushToast)
  const client = getClient()
  const connected = client.adapter === 'http'
  const operator = serviceStatus?.actor?.role === 'platform_operator'
  const [status, setStatus] = useState<RecoveryStatus | null>(null)
  const [loading, setLoading] = useState(connected)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [destinationId, setDestinationId] = useState(`${instanceId}-restored`)
  const [destinationName, setDestinationName] = useState('')
  const [plan, setPlan] = useState<RestorePlan | null>(null)
  const [approval, setApproval] = useState<RestoreApproval | null>(null)
  const [receipt, setReceipt] = useState<RestoreReceipt | null>(null)
  const [confirmApply, setConfirmApply] = useState(false)

  const reload = useCallback(async (reportError = true) => {
    if (!connected) return
    setLoading(true)
    try {
      setStatus(await client.recovery.getStatus(instanceId))
      if (reportError) setError(null)
    } catch (cause) {
      setStatus(null)
      if (reportError) {
        setError(cause instanceof Error ? cause.message : 'Recovery status is unavailable.')
      }
    } finally {
      setLoading(false)
    }
  }, [client, connected, instanceId])

  useEffect(() => {
    void reload()
  }, [reload])

  const resetDecision = () => {
    setPlan(null)
    setApproval(null)
    setReceipt(null)
    setError(null)
  }

  const createPlan = async () => {
    const backupReceiptId = status?.latest?.backupReceipt.receiptId
    const trimmedId = destinationId.trim()
    if (!backupReceiptId || status?.status !== 'verified') {
      setError('Create and verify a backup before planning a restore.')
      return
    }
    if (!INSTANCE_ID.test(trimmedId) || trimmedId === instanceId) {
      setError('Use a different lowercase instance ID containing letters, numbers, and hyphens.')
      return
    }
    setBusy(true)
    try {
      const next = await client.recovery.planRestore(instanceId, {
        backupReceiptId,
        destinationInstanceId: trimmedId,
        destinationName: destinationName.trim() || null,
      })
      setPlan(next)
      setApproval(null)
      setReceipt(null)
      setError(null)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Restore planning failed.')
    } finally {
      setBusy(false)
    }
  }

  const approve = async () => {
    if (!plan) return
    setBusy(true)
    try {
      setApproval(await client.recovery.approveRestore(instanceId, plan.planDigest))
      setError(null)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Restore approval failed.')
    } finally {
      setBusy(false)
    }
  }

  const apply = async () => {
    if (!plan || !approval) return
    setBusy(true)
    try {
      const next = await client.recovery.applyRestore(instanceId, {
        planDigest: plan.planDigest,
        approvalDigest: approval.approvalDigest,
      })
      setReceipt(next)
      setError(null)
      await reload()
      onRestored()
      pushToast({
        kind: 'success',
        title: 'Restore completed',
        body: `Created ${next.destinationInstanceId} as a separately validated instance.`,
      })
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Restore apply failed.'
      await reload(false)
      setError(message)
    } finally {
      setBusy(false)
    }
  }

  if (!connected) {
    return (
      <InlineNotice tone="informational" title="Connected recovery service required">
        The demo adapter does not simulate a durable restore. Use a connected StatePort service to plan and apply recovery.
      </InlineNotice>
    )
  }

  return (
    <div className="flex flex-col gap-4" data-testid="governed-restore-panel">
      {!operator ? (
        <InlineNotice tone="informational" title="Operator session required">
          Restore planning and approval are available only in an authenticated platform-operator session. Backup status remains read-only here.
        </InlineNotice>
      ) : null}
      {error ? (
        <InlineNotice tone="danger" title="Recovery request refused">
          {error}
        </InlineNotice>
      ) : null}
      {status?.restore.status === 'failed' ? (
        <InlineNotice
          tone={status.restore.operatorInspectionRequired ? 'danger' : 'attention'}
          title={
            status.restore.operatorInspectionRequired
              ? 'Restore needs operator inspection'
              : 'Latest restore failed'
          }
        >
          {status.restore.stagingRetained
            ? 'StatePort retained bounded staging data after the failed restore. Inspect recovery status before retrying or removing it.'
            : 'Review the persisted recovery status before creating another restore plan.'}
        </InlineNotice>
      ) : null}
      <SettingSubsection
        title="Restore as a new instance"
        description="StatePort verifies the managed backup, creates a path-free exact plan, and never overwrites the source instance. External side effects are not restored."
      >
        <SettingRow anchor="restore-status" label="Restore status">
          <ReadOnlyValue
            mono={false}
            value={loading ? 'Checking…' : status ? RESTORE_STATUS_LABEL[status.restore.status] : 'Unavailable'}
          />
        </SettingRow>
        {status?.restore.latestReceiptId ? (
          <SettingRow anchor="restore-latest-receipt" label="Latest persisted receipt">
            <ReadOnlyValue
              value={status.restore.latestReceiptId}
              copyValue={status.restore.latestReceiptId}
            />
          </SettingRow>
        ) : null}
        <SettingRow anchor="restore-backup-receipt" label="Verified backup receipt">
          <ReadOnlyValue
            value={
              loading
                ? 'Checking…'
                : status?.latest?.backupReceipt.receiptId ?? 'No verified backup'
            }
            copyValue={status?.latest?.backupReceipt.receiptId}
          />
        </SettingRow>
        <SettingRow
          anchor="restore-destination-id"
          label="New instance ID"
          description="The restore always receives a different lifecycle identity."
        >
          <input
            value={destinationId}
            onChange={(event) => {
              setDestinationId(event.target.value)
              resetDecision()
            }}
            disabled={!operator || busy}
            spellCheck={false}
            autoComplete="off"
            className="h-control w-64 max-w-full rounded-sm border border-input bg-surface px-2 font-mono text-sm text-foreground disabled:opacity-60 max-sm:w-full"
            data-testid="restore-destination-id"
          />
        </SettingRow>
        <SettingRow anchor="restore-destination-name" label="Display name" description="Optional; the source name plus “restored” is used when empty.">
          <input
            value={destinationName}
            onChange={(event) => {
              setDestinationName(event.target.value)
              resetDecision()
            }}
            disabled={!operator || busy}
            maxLength={120}
            className="h-control w-64 max-w-full rounded-sm border border-input bg-surface px-2 text-sm text-foreground disabled:opacity-60 max-sm:w-full"
          />
        </SettingRow>
        <SettingRow anchor="restore-plan" label="Exact restore plan">
          <Button
            size="sm"
            variant="outline"
            onClick={() => void createPlan()}
            disabled={!operator || busy || loading || status?.status !== 'verified'}
            data-testid="restore-plan-action"
          >
            {busy && !plan ? 'Planning…' : 'Plan restore'}
          </Button>
        </SettingRow>
      </SettingSubsection>

      {plan ? (
        <SettingSubsection title="Review exact plan" description="Approval binds the plan digest shown here; any backup, source, or destination drift causes apply to fail closed.">
          <SettingRow anchor="restore-plan-digest" label="Plan digest">
            <ReadOnlyValue value={plan.planDigest} copyValue={plan.planDigest} />
          </SettingRow>
          <SettingRow anchor="restore-plan-files" label="Validated files">
            <ReadOnlyValue mono={false} value={`${plan.dryRun.fileCount} files`} />
          </SettingRow>
          <SettingRow anchor="restore-plan-effects" label="Effect">
            <ReadOnlyValue mono={false} value={`Create ${plan.destinationInstanceId}; source unchanged; no external effects restored.`} />
          </SettingRow>
          <SettingRow anchor="restore-approve" label="Exact approval">
            {approval ? (
              <ReadOnlyValue value={approval.approvalDigest} copyValue={approval.approvalDigest} />
            ) : (
              <Button size="sm" onClick={() => void approve()} disabled={busy} data-testid="restore-approve-action">
                {busy ? 'Approving…' : 'Approve exact plan'}
              </Button>
            )}
          </SettingRow>
        </SettingSubsection>
      ) : null}

      {approval ? (
        <SettingSubsection title="Apply approved restore" description="Apply rechecks the backup bytes, source binding, destination absence, plan expiry, and approval expiry before writing.">
          <SettingRow anchor="restore-apply" label="Create new instance">
            <Button onClick={() => setConfirmApply(true)} disabled={busy || Boolean(receipt)} data-testid="restore-apply-action">
              {receipt ? 'Restore validated' : 'Apply restore'}
            </Button>
          </SettingRow>
          {receipt ? (
            <>
              <SettingRow anchor="restore-receipt" label="Restore receipt">
                <ReadOnlyValue value={receipt.receiptId} copyValue={receipt.receiptId} />
              </SettingRow>
              <SettingRow anchor="restore-receipt-digest" label="Receipt digest">
                <ReadOnlyValue value={receipt.receiptDigest} copyValue={receipt.receiptDigest} />
              </SettingRow>
            </>
          ) : null}
        </SettingSubsection>
      ) : null}

      <ConfirmDialog
        open={confirmApply}
        onOpenChange={setConfirmApply}
        title="Create the recovered instance?"
        description="The approved plan will restore verified filesystem state under a new identity."
        target={plan?.destinationInstanceId}
        effect="Create and catalog one new managed instance; leave the source unchanged."
        reversibility="The new instance can be removed separately. This does not replay or undo external actions."
        confirmLabel="Apply exact restore"
        onConfirm={apply}
      />
    </div>
  )
}
