/**
 * ReceiptDetail — the receipt drawer (receipts.md §"Receipt detail"). The
 * drawer IS the route (`…/workbench/receipts/:receiptId`): deep links open
 * it, closing navigates back to the list, Escape/back both work. On mobile
 * it becomes a full-screen sheet.
 *
 * Order: human header → what happened (plain sentences + before/after) →
 * relationships (navigable) → integrity (honest verify) → exact record
 * (mono disclosure: IDs, revisions, digests, validation, raw JSON) → the
 * single quiet caveat line (never repeated in list rows).
 */
import { format, parseISO } from 'date-fns'
import { ArrowRight, BadgeCheck, CircleX, GitCompareArrows, Loader2, ShieldCheck } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import type { Receipt } from '@/client'
import { ClientError, getClient } from '@/client'
import {
  CopyButton,
  Disclosure,
  Drawer,
  ErrorState,
  InlineNotice,
  Skeleton,
  StatusBadgeFrom,
} from '@/components'
import { Button } from '@/components/ui/button'
import { sendToBridge } from '@/features/bridge/bridgeStore'
import { cn } from '@/lib/utils'
import { receiptResultPresentation, receiptValidationPresentation } from '@/semantic'

import { actorLabel, normalizeReceiptDigest, RECEIPT_CAVEAT, VERIFY_OK_MESSAGE } from './receiptsModel'
import { registerReceiptVerifyHandler } from './detailActions'

// ─────────────────────────────────────────────────────────────────────────────
// Small pieces
// ─────────────────────────────────────────────────────────────────────────────

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section aria-label={title} className="border-b border-border/60 py-3 first:pt-0">
      <h3 className="mb-1.5 text-xs font-medium text-foreground-secondary">{title}</h3>
      {children}
    </section>
  )
}

function MonoRow({ label, value, copyLabel }: { label: string; value?: string; copyLabel?: string }) {
  if (!value) return null
  return (
    <div className="flex items-start justify-between gap-2 py-0.5">
      <span className="shrink-0 text-xs text-foreground-tertiary">{label}</span>
      <span className="flex min-w-0 items-center gap-1">
        <span className="tnum break-all text-right font-mono text-xs text-foreground-secondary">{value}</span>
        {copyLabel ? <CopyButton text={value} label={copyLabel} className="min-h-5 min-w-5" /> : null}
      </span>
    </div>
  )
}

function RelatedRow({
  to,
  label,
  id,
  onNavigate,
}: {
  to: string
  label: string
  id: string
  onNavigate?: () => void
}) {
  return (
    <Link
      to={to}
      onClick={onNavigate}
      className="flex min-h-8 items-center gap-2 rounded-sm px-1 text-sm text-foreground transition-colors duration-instant hover:bg-hover"
      data-testid={`related-${label.toLowerCase().replace(/\s+/g, '-')}`}
    >
      <ArrowRight className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
      <span className="flex-1 truncate">{label}</span>
      <span className="tnum truncate font-mono text-xs text-foreground-tertiary">{id}</span>
    </Link>
  )
}

type VerifyState = { phase: 'idle' } | { phase: 'verifying' } | { phase: 'done'; ok: boolean; detail: string }

// ─────────────────────────────────────────────────────────────────────────────
// The drawer
// ─────────────────────────────────────────────────────────────────────────────

export interface ReceiptDetailProps {
  instanceId: string
  receiptId: string
  /** Optional operation-returned digest that the durable detail must match. */
  expectedPayloadDigest?: string
  /** Native application routes must not imply Workbench availability. */
  nativeRoute?: boolean
  onClose: () => void
}

export function ReceiptDetail({
  instanceId,
  receiptId,
  expectedPayloadDigest,
  nativeRoute = false,
  onClose,
}: ReceiptDetailProps) {
  const client = getClient()
  const canVerifyIntegrity = client.adapter === 'mock'
  // Keyed fetch result: receipt/loading/error derive from whether the
  // in-flight receiptId has landed, so effects never set state synchronously.
  const [result, setResult] = useState<{ key: string; receipt: Receipt | null; error: unknown } | null>(null)
  const [verify, setVerify] = useState<VerifyState>({ phase: 'idle' })

  // A different receipt resets the verify panel (render-time adjustment).
  const [verifyFor, setVerifyFor] = useState(receiptId)
  if (verifyFor !== receiptId) {
    setVerifyFor(receiptId)
    setVerify({ phase: 'idle' })
  }

  useEffect(() => {
    let cancelled = false
    client.receipts
      .get(receiptId, instanceId)
      .then((found) => {
        if (cancelled) return
        if (found.id !== receiptId) {
          throw new ClientError(
            'validation',
            'The receipt detail response did not match the requested receipt',
            { detail: `expected ${receiptId}, got ${found.id}` },
          )
        }
        const expectedDigest = expectedPayloadDigest === undefined
          ? undefined
          : normalizeReceiptDigest(expectedPayloadDigest)
        const actualDigest = found.payloadDigest?.value === undefined
          ? undefined
          : normalizeReceiptDigest(found.payloadDigest.value)
        if (
          expectedDigest !== undefined &&
          actualDigest !== expectedDigest
        ) {
          throw new ClientError(
            'validation',
            'The receipt detail digest does not match the completed installation',
            {
              detail: `expected ${expectedDigest}, got ${actualDigest ?? 'missing'}`,
            },
          )
        }
        setResult({ key: receiptId, receipt: found, error: null })
      })
      .catch((err) => {
        if (cancelled) return
        setResult({ key: receiptId, receipt: null, error: err })
      })
    return () => {
      cancelled = true
    }
  }, [client, expectedPayloadDigest, instanceId, receiptId])

  const landed = result && result.key === receiptId ? result : null
  const loading = !landed
  const receipt = landed?.receipt ?? null
  const error = landed?.error ?? null

  const runVerify = useCallback(async () => {
    if (!canVerifyIntegrity) return
    setVerify({ phase: 'verifying' })
    try {
      const result = await client.receipts.verify(receiptId)
      setVerify({ phase: 'done', ok: result.ok, detail: result.detail })
    } catch (err) {
      setVerify({
        phase: 'done',
        ok: false,
        detail: err instanceof Error ? err.message : 'The integrity check could not be completed.',
      })
    }
  }, [canVerifyIntegrity, client, receiptId])

  // The palette's "Verify receipt integrity" command triggers this drawer.
  useEffect(() => {
    if (!canVerifyIntegrity) {
      registerReceiptVerifyHandler(null)
      return
    }
    registerReceiptVerifyHandler(() => void runVerify())
    return () => registerReceiptVerifyHandler(null)
  }, [canVerifyIntegrity, runVerify])

  const fullTime = receipt ? format(parseISO(receipt.createdAt), 'PPpp') : undefined

  return (
    <Drawer
      open
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
      title={receipt?.actionName ?? 'Receipt'}
      description={
        receipt ? (
          <span className="flex flex-wrap items-center gap-2">
            <StatusBadgeFrom presentation={receiptResultPresentation(receipt.result)} />
            <span className="tnum font-mono text-xs">{fullTime}</span>
          </span>
        ) : undefined
      }
      width={480}
      className="max-md:inset-0 max-md:max-h-none max-md:rounded-none"
      footer={
        // The one quiet caveat — here in the detail footer, never per row.
        <p className="w-full text-left text-xs text-foreground-tertiary" data-testid="receipt-caveat">
          {RECEIPT_CAVEAT}
        </p>
      }
    >
      <div data-testid="receipt-detail" className="flex flex-col">
        {loading ? (
          <div className="flex flex-col gap-2 py-2" role="status" aria-label="Loading receipt…">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-1/2" />
            <Skeleton className="h-20 w-full" />
          </div>
        ) : error || !receipt ? (
          <ErrorState
            title="Receipt not available"
            error={error ?? 'This receipt could not be found.'}
            preservedNote="The list behind this drawer still has your filters."
            onRetry={onClose}
            retryLabel="Back to receipts"
          />
        ) : (
          <>
            {/* 2 · What happened — plain sentences + before/after */}
            <DetailSection title="What happened">
              <p className="text-sm text-foreground">{receipt.summary}</p>
              {receipt.beforeSummary || receipt.afterSummary ? (
                <dl className="mt-2 flex flex-col gap-1">
                  {receipt.beforeSummary ? (
                    <div className="flex gap-2 text-xs">
                      <dt className="w-12 shrink-0 text-foreground-tertiary">Before</dt>
                      <dd className="text-foreground-secondary">{receipt.beforeSummary}</dd>
                    </div>
                  ) : null}
                  {receipt.afterSummary ? (
                    <div className="flex gap-2 text-xs">
                      <dt className="w-12 shrink-0 text-foreground-tertiary">After</dt>
                      <dd className="text-foreground-secondary">{receipt.afterSummary}</dd>
                    </div>
                  ) : null}
                </dl>
              ) : null}
              {receipt.diff ? (
                <div className="mt-2">
                  <div className="flex items-center gap-2 text-xs text-foreground-secondary">
                    <GitCompareArrows className="size-3.5" aria-hidden="true" />
                    <span className="tnum font-mono">
                      +{receipt.diff.addedLines} −{receipt.diff.removedLines}
                    </span>
                    {!nativeRoute ? (
                      <Link
                        to={`/app/${instanceId}/workbench/files`}
                        className="text-accent transition-colors duration-instant hover:text-accent-hover"
                      >
                        Open diff
                      </Link>
                    ) : null}
                  </div>
                  <Disclosure title="Compare before / after" className="mt-1">
                    <pre
                      className="mt-1 max-h-56 overflow-auto rounded-sm border border-border bg-sunken p-2 font-mono text-xs text-foreground-secondary"
                      data-testid="receipt-diff"
                    >
                      {receipt.diff.unified}
                    </pre>
                  </Disclosure>
                </div>
              ) : null}
            </DetailSection>

            {/* 3 · Relationships — navigable rows */}
            {receipt.relatedApprovalId ||
            receipt.relatedConversationId ||
            (!nativeRoute && (receipt.relatedOperationId || receipt.relatedPlanId)) ? (
              <DetailSection title="Relationships">
                <div className="flex flex-col">
                  {receipt.relatedApprovalId ? (
                    <RelatedRow to={`/approvals/${receipt.relatedApprovalId}`} label="Related approval" id={receipt.relatedApprovalId} />
                  ) : null}
                  {receipt.relatedOperationId && !nativeRoute ? (
                    <RelatedRow
                      to={`/app/${instanceId}/workbench/deployments`}
                      label="Related operation"
                      id={receipt.relatedOperationId}
                    />
                  ) : null}
                  {receipt.relatedPlanId && !nativeRoute ? (
                    <RelatedRow to={`/app/${instanceId}/workbench/deployments`} label="Related plan" id={receipt.relatedPlanId} />
                  ) : null}
                  {receipt.relatedConversationId ? (
                    <RelatedRow
                      to={`/app/${instanceId}/conversation`}
                      label="Related conversation"
                      id={receipt.relatedConversationId}
                      onNavigate={() =>
                        sendToBridge({
                          kind: 'receipt',
                          instanceId,
                          receiptId: receipt.id,
                        })
                      }
                    />
                  ) : null}
                </div>
              </DetailSection>
            ) : null}

            {!nativeRoute ? (
              <DetailSection title="Continue">
                <RelatedRow
                  to={`/app/${instanceId}/conversation`}
                  label="Review receipt in Conversation"
                  id={receipt.id}
                  onNavigate={() =>
                    sendToBridge({
                      kind: 'receipt',
                      instanceId,
                      receiptId: receipt.id,
                    })
                  }
                />
                <p className="mt-1 px-1 text-xs text-foreground-tertiary">
                  Conversation receives a removable reference. No action is executed and no
                  canonical state is changed.
                </p>
              </DetailSection>
            ) : null}

            {/* 4 · Integrity — mock-only until a production endpoint exists. */}
            {canVerifyIntegrity ? (
              <DetailSection title="Integrity">
                <div className="flex items-center gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => void runVerify()}
                    disabled={verify.phase === 'verifying'}
                    className="h-7 gap-1.5 rounded-sm text-xs"
                    data-testid="receipt-verify"
                  >
                    {verify.phase === 'verifying' ? (
                      <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
                    ) : (
                      <ShieldCheck className="size-3.5" aria-hidden="true" />
                    )}
                    {verify.phase === 'verifying' ? 'Verifying…' : 'Verify integrity'}
                  </Button>
                  <span className="text-xs text-foreground-tertiary">Recomputes the recorded digests.</span>
                </div>
                {verify.phase === 'done' ? (
                  <InlineNotice
                    tone={verify.ok ? 'informational' : 'danger'}
                    icon={verify.ok ? BadgeCheck : CircleX}
                    title={verify.ok ? VERIFY_OK_MESSAGE : 'Integrity check failed'}
                    className={cn('mt-2', verify.ok && 'border-status-success-border bg-status-success-bg text-status-success')}
                  >
                    <span className="text-xs">{verify.detail}</span>
                    {!verify.ok ? (
                      <span className="mt-1 flex items-center gap-1 text-xs">
                        <CopyButton
                          text={`receipt: ${receipt.id}\npayloadDigest: ${receipt.payloadDigest?.value ?? 'none'}\nplanDigest: ${receipt.planDigest?.value ?? 'none'}\nverify: ${verify.detail}`}
                          label="Copy diagnostic details"
                        />
                        <span className="text-foreground-tertiary">Copy diagnostic details</span>
                      </span>
                    ) : null}
                  </InlineNotice>
                ) : null}
              </DetailSection>
            ) : null}

            {/* 5 · Exact record — mono disclosure */}
            <DetailSection title="Exact record">
              <Disclosure title="IDs, revisions, and digests" defaultOpen={false}>
                <div className="rounded-sm border border-border bg-sunken px-2 py-1" data-testid="receipt-exact-record">
                  <MonoRow label="Receipt ID" value={receipt.id} copyLabel="Copy receipt ID" />
                  <MonoRow label="Raw event kind" value={receipt.eventKind} />
                  <MonoRow label="Instance ID" value={receipt.instanceId} />
                  <MonoRow label="Application ID" value={receipt.packageId} />
                  <MonoRow label="Actor" value={`${receipt.actor} (${actorLabel(receipt.actor)})`} />
                  <MonoRow label="Recorded at" value={receipt.createdAt} />
                  <MonoRow label="Expected revision" value={receipt.expectedRevision} />
                  <MonoRow label="Result revision" value={receipt.resultRevision} />
                  <MonoRow label="Plan digest" value={receipt.planDigest?.value} copyLabel="Copy plan digest" />
                  <MonoRow label="Payload digest" value={receipt.payloadDigest?.value} copyLabel="Copy payload digest" />
                  <div className="flex items-center justify-between gap-2 py-0.5">
                    <span className="shrink-0 text-xs text-foreground-tertiary">Validation</span>
                    <StatusBadgeFrom presentation={receiptValidationPresentation(receipt.validation.state)} className="text-xs" />
                  </div>
                  <p className="py-0.5 text-right text-xs text-foreground-tertiary">{receipt.validation.detail}</p>
                </div>
              </Disclosure>
              <Disclosure
                title="Raw JSON"
                className="mt-1"
                headerExtra={<CopyButton text={receipt.rawJson} label="Copy raw JSON" />}
              >
                <pre
                  className="mt-1 max-h-72 overflow-auto rounded-sm border border-border bg-sunken p-2 font-mono text-xs text-foreground-secondary"
                  data-testid="receipt-raw-json"
                >
                  {receipt.rawJson}
                </pre>
              </Disclosure>
            </DetailSection>
          </>
        )}
      </div>
    </Drawer>
  )
}
