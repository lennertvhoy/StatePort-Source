/**
 * Application context lifecycle — the backend-owned operational projection.
 *
 * This surface intentionally does not expose raw prompts or claim to render a
 * complete StatePack. It shows the exact policy/base/continuity identities the
 * service publishes and binds manual transitions to those identities.
 */
import { useEffect, useMemo, useState } from 'react'

import type {
  ContextLifecycle,
  ContextPreference,
  ContextTransitionBinding,
  ContextTransitionResult,
} from '@/client'
import { getClient } from '@/client'
import { ConfirmDialog, ErrorState, InlineNotice, SkeletonRows, StatusBadge } from '@/components'
import { Button } from '@/components/ui/button'

import { ReadOnlyValue, SelectControl, SettingRow, SettingSubsection } from './controls'

type TransitionKind = 'compact' | 'handoff'

function continuityReason(reason: string | null | undefined): string {
  switch (reason) {
    case 'conversation_context_not_available':
      return 'No current conversation context is available. Send a message before creating a compacted context or handoff.'
    case 'context_manifest_stale':
      return 'The current context manifest is stale. Refresh after the conversation projection has been reconciled.'
    case null:
    case undefined:
      return 'No current continuity binding is available.'
    default:
      return reason.replaceAll('_', ' ')
  }
}

function bindingFor(lifecycle: ContextLifecycle): ContextTransitionBinding | null {
  const { expectedBaseSha, expectedPolicyDigest, continuityDigest } = lifecycle.continuity
  if (!expectedBaseSha || !expectedPolicyDigest || !continuityDigest) return null
  return {
    expectedBaseSha,
    expectedPolicyDigest,
    expectedContinuityDigest: continuityDigest,
  }
}

function messageFor(error: unknown): string {
  return error instanceof Error ? error.message : 'The context operation failed.'
}

function humanList(values: readonly string[]): string {
  return values.length > 0
    ? values.map((value) => value.replaceAll('_', ' ')).join(', ')
    : 'None declared'
}

export function ContextLifecycleGroup({ instanceId }: { instanceId: string }) {
  const [lifecycle, setLifecycle] = useState<ContextLifecycle | null>(null)
  const [loadError, setLoadError] = useState<unknown>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [result, setResult] = useState<ContextTransitionResult | null>(null)
  const [busy, setBusy] = useState<ContextPreference | TransitionKind | null>(null)
  const [confirming, setConfirming] = useState<TransitionKind | null>(null)
  const [nonce, setNonce] = useState(0)

  useEffect(() => {
    let cancelled = false
    getClient()
      .context.getLifecycle(instanceId)
      .then((next) => {
        if (cancelled) return
        setLifecycle(next)
        setLoadError(null)
      })
      .catch((error: unknown) => {
        if (!cancelled) setLoadError(error)
      })
    return () => {
      cancelled = true
    }
  }, [instanceId, nonce])

  const binding = useMemo(() => (lifecycle ? bindingFor(lifecycle) : null), [lifecycle])

  const retry = () => {
    setLifecycle(null)
    setLoadError(null)
    setActionError(null)
    setNonce((value) => value + 1)
  }

  const updatePreference = async (mode: ContextPreference) => {
    if (!lifecycle || mode === lifecycle.preference || busy) return
    setBusy(mode)
    setActionError(null)
    setResult(null)
    try {
      const next = await getClient().context.updatePreference(instanceId, {
        expectedPolicyDigest: lifecycle.policyDigest.value,
        mode,
      })
      setLifecycle(next)
    } catch (error) {
      setActionError(messageFor(error))
    } finally {
      setBusy(null)
    }
  }

  const runTransition = async (kind: TransitionKind) => {
    if (!binding || busy) return
    setBusy(kind)
    setActionError(null)
    setResult(null)
    try {
      const next =
        kind === 'compact'
          ? await getClient().context.compact(instanceId, binding)
          : await getClient().context.handoff(instanceId, binding)
      setLifecycle(next.lifecycle)
      setResult(next)
    } catch (error) {
      setActionError(messageFor(error))
    } finally {
      setBusy(null)
    }
  }

  if (!lifecycle && !loadError) {
    return (
      <div className="py-2" data-testid="context-lifecycle-loading">
        <SkeletonRows rows={6} />
      </div>
    )
  }

  if (!lifecycle) {
    return (
      <ErrorState
        title="Context lifecycle couldn’t be loaded"
        error={loadError}
        preservedNote="Canonical application state and the current conversation were not changed."
        onRetry={retry}
        className="min-h-64"
      />
    )
  }

  const selectedMode = lifecycle.availableModes.find((mode) => mode.id === lifecycle.preference)
  const compactAvailable = lifecycle.continuity.manualCompactAvailable && binding !== null
  const handoffAvailable = lifecycle.continuity.manualHandoffAvailable && binding !== null

  return (
    <div className="flex flex-col gap-5" data-testid="app-settings-context-lifecycle">
      <InlineNotice tone="informational" title="Operational context, not application truth">
        Compaction and handoff preserve conversation continuity and leave canonical application state unchanged. This
        view does not accept raw prompt overrides.
      </InlineNotice>

      {actionError ? (
        <InlineNotice tone="danger" title="Context operation refused">
          {actionError} Refresh before retrying if the policy, base commit, or continuity identity changed.
        </InlineNotice>
      ) : null}

      {result ? (
        <InlineNotice tone="informational" title="Context transition recorded">
          <span>{result.summary}</span>
          {result.receiptId ? (
            <span className="mt-1 block font-mono text-xs" data-testid="context-transition-receipt">
              Receipt: {result.receiptId}
            </span>
          ) : null}
        </InlineNotice>
      ) : null}

      <SettingSubsection
        title="Context preference"
        description="The service resolves this preference with its policy. Browser-supplied prompt text is never accepted."
      >
        <SettingRow
          anchor="context-preference"
          label="Context depth"
          description={selectedMode?.description ?? 'The effective context mode for this application.'}
        >
          <SelectControl
            value={lifecycle.preference}
            options={
              lifecycle.availableModes.length > 0
                ? lifecycle.availableModes.map((mode) => ({ value: mode.id, label: mode.label }))
                : [{ value: lifecycle.preference, label: lifecycle.preference }]
            }
            disabled={busy !== null}
            onChange={(mode) => void updatePreference(mode as ContextPreference)}
          />
        </SettingRow>
        <SettingRow
          anchor="context-raw-prompts"
          label="Raw prompt overrides"
          description="Policy text remains backend-owned."
        >
          <ReadOnlyValue
            mono={false}
            value={lifecycle.rawPromptFieldsAllowed ? 'Accepted by this contract' : 'Not accepted by this contract'}
          />
        </SettingRow>
        <SettingRow anchor="context-usage" label="Current estimated use">
          <ReadOnlyValue mono={false} value={lifecycle.usageDisplay} />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection
        title="Effective policy"
        description="Resolved backend policy facts. The most restrictive applicable layer wins."
      >
        <SettingRow anchor="context-budget-maximum" label="Maximum input budget">
          <ReadOnlyValue
            mono={false}
            value={`${lifecycle.effectivePolicy.budget.maximumInputTokens.toLocaleString()} tokens`}
          />
        </SettingRow>
        <SettingRow anchor="context-budget-preferred" label="Preferred input budget">
          <ReadOnlyValue
            mono={false}
            value={`${lifecycle.effectivePolicy.budget.preferredInputTokens.toLocaleString()} tokens`}
          />
        </SettingRow>
        <SettingRow anchor="context-included" label="Included categories">
          <ReadOnlyValue
            mono={false}
            value={humanList(lifecycle.effectivePolicy.contextCategories.included)}
          />
        </SettingRow>
        <SettingRow anchor="context-excluded" label="Excluded categories">
          <ReadOnlyValue
            mono={false}
            value={humanList(lifecycle.effectivePolicy.contextCategories.excluded)}
          />
        </SettingRow>
        <SettingRow anchor="context-preserved" label="Preserved through compaction">
          <ReadOnlyValue
            mono={false}
            value={humanList(lifecycle.effectivePolicy.compression.preserve)}
          />
        </SettingRow>
        <SettingRow anchor="context-policy-sources" label="Policy sources">
          <ReadOnlyValue
            mono={false}
            value={
              lifecycle.effectivePolicy.sourcePolicies.length > 0
                ? lifecycle.effectivePolicy.sourcePolicies
                    .map((source) => `${source.scope}: ${source.policyId}`)
                    .join(', ')
                : 'No policy source recorded'
            }
          />
        </SettingRow>
        <SettingRow anchor="context-policy-unresolved" label="Unresolved policy scopes">
          <ReadOnlyValue
            mono={false}
            value={humanList(lifecycle.effectivePolicy.unresolvedPolicyScopes)}
          />
        </SettingRow>
        <SettingRow anchor="context-record-count" label="Recorded transitions">
          <ReadOnlyValue
            mono={false}
            value={lifecycle.storedRecordCount.toLocaleString()}
          />
        </SettingRow>
        <SettingRow anchor="context-default-evidence" label="Default-policy evidence">
          <ReadOnlyValue
            mono={false}
            value="Candidate default — not benchmarked"
          />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection
        title="Repository identity"
        description="The exact Git snapshot used by continuity checks. A dirty worktree is not hidden."
      >
        {lifecycle.gitIdentity ? (
          <>
            <SettingRow anchor="context-repository-id" label="Repository identity">
              <ReadOnlyValue
                value={lifecycle.gitIdentity.repositoryId}
                copyValue={lifecycle.gitIdentity.repositoryId}
              />
            </SettingRow>
            <SettingRow anchor="context-git-branch" label="Branch">
              <ReadOnlyValue
                value={lifecycle.gitIdentity.branch}
                copyValue={lifecycle.gitIdentity.branch}
              />
            </SettingRow>
            <SettingRow anchor="context-git-head" label="Head commit">
              <ReadOnlyValue
                value={lifecycle.gitIdentity.headSha}
                copyValue={lifecycle.gitIdentity.headSha}
              />
            </SettingRow>
            <SettingRow anchor="context-git-tree" label="Tree">
              <ReadOnlyValue
                value={lifecycle.gitIdentity.treeSha}
                copyValue={lifecycle.gitIdentity.treeSha}
              />
            </SettingRow>
            <SettingRow anchor="context-worktree" label="Worktree">
              <ReadOnlyValue
                mono={false}
                value={lifecycle.gitIdentity.worktreeClean ? 'Clean' : 'Dirty'}
              />
            </SettingRow>
            <SettingRow anchor="context-worktree-digest" label="Worktree status digest">
              <ReadOnlyValue
                value={lifecycle.gitIdentity.worktreeStatusDigest}
                copyValue={lifecycle.gitIdentity.worktreeStatusDigest}
              />
            </SettingRow>
          </>
        ) : (
          <InlineNotice tone="attention">
            Git identity is unavailable
            {lifecycle.gitIdentityReason
              ? ` — ${lifecycle.gitIdentityReason.replaceAll('_', ' ')}`
              : '.'}
          </InlineNotice>
        )}
      </SettingSubsection>

      <SettingSubsection
        title="Continuity binding"
        description="Manual actions bind to these exact identities and fail closed when any identity becomes stale."
      >
        <SettingRow anchor="context-continuity-state" label="Continuity">
          <StatusBadge
            state={lifecycle.continuity.available ? 'neutral' : 'attention'}
            label={lifecycle.continuity.available ? 'Available' : 'Unavailable'}
          />
        </SettingRow>
        {!lifecycle.continuity.available ? (
          <div className="border-b border-border/60 py-2 text-sm text-foreground-secondary">
            {continuityReason(lifecycle.continuity.reasonCode)}
          </div>
        ) : null}
        <SettingRow anchor="context-policy-digest" label="Effective policy digest">
          <ReadOnlyValue value={lifecycle.policyDigest.value} copyValue={lifecycle.policyDigest.value} />
        </SettingRow>
        <SettingRow anchor="context-base-sha" label="Expected base commit">
          <ReadOnlyValue
            value={lifecycle.continuity.expectedBaseSha ?? 'Unavailable'}
            copyValue={lifecycle.continuity.expectedBaseSha ?? undefined}
          />
        </SettingRow>
        <SettingRow anchor="context-continuity-digest" label="Continuity digest">
          <ReadOnlyValue
            value={lifecycle.continuity.continuityDigest ?? 'Unavailable'}
            copyValue={lifecycle.continuity.continuityDigest ?? undefined}
          />
        </SettingRow>
        <SettingRow anchor="context-conversation-id" label="Conversation identity">
          <ReadOnlyValue
            value={lifecycle.continuity.conversationId ?? 'Unavailable'}
            copyValue={lifecycle.continuity.conversationId ?? undefined}
          />
        </SettingRow>
        {lifecycle.continuity.workstreamId ? (
          <SettingRow anchor="context-workstream-id" label="Workstream identity">
            <ReadOnlyValue value={lifecycle.continuity.workstreamId} copyValue={lifecycle.continuity.workstreamId} />
          </SettingRow>
        ) : null}
      </SettingSubsection>

      <SettingSubsection
        title="Manual transitions"
        description="These operational actions produce receipts. Approval is not inferred, and neither action applies canonical state."
      >
        <SettingRow
          anchor="context-compact"
          label="Compact current context"
          description="Create the policy-bounded compacted context while retaining the logical conversation."
        >
          <Button
            variant="outline"
            size="sm"
            disabled={!compactAvailable || busy !== null}
            onClick={() => setConfirming('compact')}
            data-testid="context-compact"
          >
            {busy === 'compact' ? 'Compacting…' : 'Compact context'}
          </Button>
        </SettingRow>
        <SettingRow
          anchor="context-handoff"
          label="Create provider handoff"
          description="Create a durable handoff artifact for a fresh provider session with the same logical conversation."
        >
          <Button
            variant="outline"
            size="sm"
            disabled={!handoffAvailable || busy !== null}
            onClick={() => setConfirming('handoff')}
            data-testid="context-handoff"
          >
            {busy === 'handoff' ? 'Creating…' : 'Create handoff'}
          </Button>
        </SettingRow>
      </SettingSubsection>

      {lifecycle.segments.length > 0 ? (
        <SettingSubsection
          title="Scenario context composition"
          description="Illustrative segment data is available in Scenario Lab; production exposes no segment content here."
        >
          <ul className="divide-y divide-border/60" data-testid="context-segments">
            {lifecycle.segments.map((segment) => (
              <li key={segment.id} className="flex min-h-10 items-center justify-between gap-3 py-2 text-sm">
                <span className="min-w-0 truncate text-foreground">{segment.label}</span>
                <span className="shrink-0 text-xs text-foreground-secondary">
                  {segment.tokens.toLocaleString()} tokens{segment.pinned ? ' · retained' : ''}
                </span>
              </li>
            ))}
          </ul>
        </SettingSubsection>
      ) : (
        <p className="text-xs text-foreground-tertiary">
          Per-segment provenance, redactions, sensitivity, and lossiness are not exposed by the current browser
          contract. Their absence is not treated as proof that no such policy exists.
        </p>
      )}

      <ConfirmDialog
        open={confirming !== null}
        onOpenChange={(open) => {
          if (!open) setConfirming(null)
        }}
        title={confirming === 'handoff' ? 'Create context handoff?' : 'Compact current context?'}
        description={
          confirming === 'handoff'
            ? 'StatePort will create a durable handoff artifact for a fresh provider session.'
            : 'StatePort will compact eligible context under the current effective policy.'
        }
        target={lifecycle.continuity.conversationId ?? instanceId}
        effect="The exact base, policy, and continuity identities are rechecked. Canonical application state remains unchanged."
        reversibility="The operation is recorded by receipt; the conversation remains authoritative for continuity."
        confirmLabel={confirming === 'handoff' ? 'Create handoff' : 'Compact context'}
        onConfirm={() => (confirming ? runTransition(confirming) : undefined)}
      />
    </div>
  )
}
