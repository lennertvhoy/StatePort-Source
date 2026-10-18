/**
 * Exact-on-demand execution evidence.
 *
 * The RunBundle projection is deliberately path-free. StateBench is fetched
 * only when the application has a usable benchmark_evidence capability.
 * Missing evidence, transport failures, and benchmark facts remain distinct;
 * no aggregate success verdict or receipt identity is synthesized.
 */
import { CircleCheck, CircleX, FileJson, Receipt, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { ClientError } from '@/client'
import type { RunBundle, RunRecord, StateBenchResult } from '@/client'
import { getClient } from '@/client'
import {
  CopyButton,
  Disclosure,
  Drawer,
  InlineNotice,
  OperationStateLabel,
  Skeleton,
  TimeAgo,
} from '@/components'
import { operationStatePresentation } from '@/semantic'

import { runStatusLabel, safeEvidenceValue } from './runsModel'

type LoadState<T> =
  | { status: 'loading' }
  | { status: 'error'; detail: string }
  | { status: 'ready'; value: T }

type BenchmarkLoadState =
  | LoadState<StateBenchResult | null>
  | { status: 'disabled' }

function errorDetail(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function evidenceAbsent(error: unknown): boolean {
  return error instanceof ClientError && error.status === 404
}

function ReceiptIdentity({
  receiptId,
  receiptBasePath,
}: {
  receiptId: string
  receiptBasePath?: string
}) {
  if (!receiptBasePath) {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-foreground-secondary">
        <Receipt className="size-3" aria-hidden="true" />
        <span className="tnum font-mono">{receiptId}</span>
      </span>
    )
  }
  return (
    <Link
      to={`${receiptBasePath}/${receiptId}`}
      className="inline-flex items-center gap-1 text-xs text-accent hover:underline"
    >
      <Receipt className="size-3" aria-hidden="true" />
      <span className="tnum font-mono">{receiptId}</span>
    </Link>
  )
}

function RunEvidenceContent({
  run,
  benchmarkEnabled,
  receiptBasePath,
}: {
  run: RunRecord
  benchmarkEnabled: boolean
  receiptBasePath?: string
}) {
  const [bundle, setBundle] = useState<LoadState<RunBundle>>({ status: 'loading' })
  const [statebench, setStatebench] = useState<BenchmarkLoadState>(
    benchmarkEnabled ? { status: 'loading' } : { status: 'disabled' },
  )

  useEffect(() => {
    let cancelled = false
    const client = getClient()
    client.runs
      .getBundle(run.id)
      .then((value) => {
        if (!cancelled) setBundle({ status: 'ready', value })
      })
      .catch((error: unknown) => {
        if (!cancelled) setBundle({ status: 'error', detail: errorDetail(error) })
      })
    if (benchmarkEnabled) {
      client.runs
        .getStateBench(run.id)
        .then((value) => {
          if (!cancelled) setStatebench({ status: 'ready', value })
        })
        .catch((error: unknown) => {
          if (cancelled) return
          setStatebench(
            evidenceAbsent(error)
              ? { status: 'ready', value: null }
              : { status: 'error', detail: errorDetail(error) },
          )
        })
    }
    return () => {
      cancelled = true
    }
  }, [benchmarkEnabled, run.id])

  const safeRaw = safeEvidenceValue({
    run,
    bundle: bundle.status === 'ready' ? bundle.value : undefined,
    stateBench: statebench.status === 'ready' ? statebench.value : undefined,
  })

  return (
    <div className="flex flex-col gap-5" data-testid="run-detail">
      <section aria-label="Run identity" className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <OperationStateLabel state={run.state} />
          <span className="rounded-sm bg-sunken px-1.5 py-0.5 text-xs font-medium text-foreground-secondary">
            {runStatusLabel(run.status)}
          </span>
          {run.lifecycleState ? (
            <span className="tnum font-mono text-xs text-foreground-tertiary">
              {run.lifecycleState}
            </span>
          ) : null}
        </div>
        <dl className="grid gap-x-4 gap-y-1 text-xs sm:grid-cols-2">
          <div className="flex items-baseline gap-2">
            <dt className="shrink-0 font-medium text-foreground-secondary">Revision</dt>
            <dd className="tnum font-mono text-foreground">{run.revision}</dd>
          </div>
          <div className="flex items-baseline gap-2">
            <dt className="shrink-0 font-medium text-foreground-secondary">Created</dt>
            <dd className="text-foreground"><TimeAgo date={run.createdAt} /></dd>
          </div>
        </dl>
      </section>

      <section aria-label="RunBundle" className="flex flex-col gap-2">
        <h3 className="text-sm font-medium text-foreground">RunBundle</h3>
        {bundle.status === 'loading' ? (
          <Skeleton className="h-24" />
        ) : bundle.status === 'error' ? (
          <InlineNotice tone="danger" title="RunBundle could not be loaded">
            {bundle.detail}
          </InlineNotice>
        ) : (
          <dl
            className="grid gap-x-4 gap-y-2 border-y border-border py-3 text-xs sm:grid-cols-2"
            data-testid="run-bundle"
          >
            <div>
              <dt className="text-foreground-tertiary">Integrity</dt>
              <dd className="mt-0.5 flex items-center gap-1 font-medium text-foreground">
                {bundle.value.verified ? (
                  <ShieldCheck className="size-3.5 text-status-success" aria-hidden="true" />
                ) : (
                  <CircleX className="size-3.5 text-status-danger" aria-hidden="true" />
                )}
                {bundle.value.verified ? 'Verified' : 'Not verified'}
              </dd>
            </div>
            <div>
              <dt className="text-foreground-tertiary">Applied variant</dt>
              <dd className="mt-0.5 font-medium text-foreground">
                {bundle.value.applied ? 'Applied bundle' : 'Execution bundle'}
              </dd>
            </div>
            <div>
              <dt className="text-foreground-tertiary">Files</dt>
              <dd className="tnum mt-0.5 font-mono text-foreground">{bundle.value.fileCount}</dd>
            </div>
            <div>
              <dt className="text-foreground-tertiary">Content digest</dt>
              <dd className="tnum mt-0.5 truncate font-mono text-foreground" title={bundle.value.contentDigest.value}>
                {bundle.value.contentDigest.value}
              </dd>
            </div>
          </dl>
        )}
        <p className="text-xs text-foreground-tertiary">
          This projection exposes immutable identity and integrity facts; host-local bundle paths are withheld.
        </p>
      </section>

      <section aria-label="Lifecycle journal" className="flex flex-col gap-2">
        <h3 className="text-sm font-medium text-foreground">Lifecycle journal</h3>
        {!run.events?.length ? (
          <p className="text-xs text-foreground-tertiary" data-testid="run-events-empty">
            No lifecycle events are exposed by this run projection.
          </p>
        ) : (
          <ol className="divide-y divide-border border-y border-border" data-testid="run-events">
            {run.events.map((event, index) => (
              <li key={`${event.type}-${event.at ?? 'unknown'}-${index}`} className="grid gap-1 py-2 text-xs sm:grid-cols-[8rem_1fr_auto]">
                <span className="font-medium text-foreground">{event.type.replaceAll('_', ' ')}</span>
                <span className="text-foreground-secondary">
                  {[event.from, event.to].filter(Boolean).join(' → ') || event.reason || 'No transition detail'}
                </span>
                <span className="tnum font-mono text-foreground-tertiary">
                  {event.at ? <TimeAgo date={event.at} /> : 'Time not exposed'}
                </span>
              </li>
            ))}
          </ol>
        )}
      </section>

      <section aria-label="Receipt" className="flex flex-col gap-2">
        <h3 className="text-sm font-medium text-foreground">Receipt</h3>
        {run.receiptId ? (
          <ReceiptIdentity receiptId={run.receiptId} receiptBasePath={receiptBasePath} />
        ) : run.receipt ? (
          <p className="text-xs text-foreground-secondary" data-testid="run-receipt-unindexed">
            A receipt payload is recorded, but this projection does not expose a receipt index identity.
          </p>
        ) : (
          <p className="text-xs text-foreground-tertiary" data-testid="run-receipts-empty">
            No receipt is exposed by this run projection.
          </p>
        )}
        <p className="text-xs text-foreground-tertiary">
          A receipt proves its recorded operation only.
        </p>
      </section>

      <section aria-label="StateBench evidence" className="flex flex-col gap-2">
        <h3 className="text-sm font-medium text-foreground">StateBench evidence</h3>
        {statebench.status === 'disabled' ? (
          <p className="text-xs text-foreground-tertiary" data-testid="run-statebench-gated">
            This application does not expose benchmark evidence.
          </p>
        ) : statebench.status === 'loading' ? (
          <Skeleton className="h-20" />
        ) : statebench.status === 'error' ? (
          <InlineNotice tone="danger" title="StateBench evidence could not be loaded">
            {statebench.detail}
          </InlineNotice>
        ) : statebench.value === null ? (
          <p className="text-xs text-foreground-tertiary" data-testid="run-statebench-empty">
            No retrievable StateBench evidence is recorded for this run.
          </p>
        ) : (
          <div className="flex flex-col gap-2" data-testid="run-statebench">
            <InlineNotice tone="informational">
              This is a non-authoritative evidence vector. Producer claims are not trusted as evaluator truth.
            </InlineNotice>
            <ul className="divide-y divide-border border-y border-border">
              {statebench.value.checks.map((check) => {
                const presentation = operationStatePresentation(check.state)
                const Icon = presentation.state === 'success' ? CircleCheck : CircleX
                return (
                  <li key={check.id} className="flex items-start gap-2 py-2" data-testid="statebench-check">
                    <Icon
                      className={`mt-0.5 size-3.5 shrink-0 ${
                        presentation.state === 'success'
                          ? 'text-status-success'
                          : 'text-status-danger'
                      }`}
                      aria-hidden="true"
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block text-xs font-medium text-foreground">{check.title}</span>
                      <span className="block text-xs text-foreground-secondary">{presentation.label}</span>
                      {check.detail ? (
                        <span className="block text-xs text-foreground-tertiary">{check.detail}</span>
                      ) : null}
                    </span>
                  </li>
                )
              })}
            </ul>
          </div>
        )}
      </section>

      <Disclosure
        title="Raw evidence JSON"
        headerExtra={<CopyButton text={JSON.stringify(safeRaw, null, 2)} label="Copy safe run evidence JSON" />}
      >
        <div className="mt-1 flex items-center gap-1 pb-1 text-xs text-foreground-tertiary">
          <FileJson className="size-3.5" aria-hidden="true" />
          Exact client projections with absolute host paths withheld.
        </div>
        <pre
          className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-sm border border-border bg-sunken p-2 font-mono text-xs text-foreground-secondary"
          data-testid="run-raw-json"
        >
          {JSON.stringify(safeRaw, null, 2)}
        </pre>
      </Disclosure>
    </div>
  )
}

export function RunDetailDrawer({
  run,
  benchmarkEnabled,
  receiptBasePath,
  onClose,
}: {
  run: RunRecord
  benchmarkEnabled: boolean
  receiptBasePath?: string
  onClose: () => void
}) {
  return (
    <Drawer
      open
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
      title={run.id}
      description={
        <>
          Action <span className="font-mono">{run.actionId}</span> · engine{' '}
          <span className="font-mono">{run.engineId}</span>
        </>
      }
      width={540}
    >
      <RunEvidenceContent
        key={run.id}
        run={run}
        benchmarkEnabled={benchmarkEnabled}
        receiptBasePath={receiptBasePath}
      />
    </Drawer>
  )
}
