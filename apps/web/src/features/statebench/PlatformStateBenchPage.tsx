/**
 * Operator-only StateBench RunBundle evidence.
 *
 * The normal-user route intentionally stops after /v1/status. Only the exact
 * platform-operator permission projection may trigger the matrix request, and
 * the service independently rechecks that authority.
 */
import { ArrowLeft, Database, RefreshCw, SearchCheck } from 'lucide-react'
import type { ReactNode } from 'react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import {
  canInspectPlatformStateBench,
  getClient,
  type LocalServiceStatus,
  type PlatformStateBenchRow,
  type PlatformStateBenchView,
} from '@/client'
import {
  CopyButton,
  Disclosure,
  Drawer,
  EmptyState,
  ErrorState,
  InlineNotice,
  SkeletonRows,
  StatusBadge,
} from '@/components'
import { Button } from '@/components/ui/button'

type LoadResult = {
  key: number
  status: LocalServiceStatus | null
  matrix: PlatformStateBenchView | null
  error: unknown
}

function FactRow({
  label,
  value,
  copy,
}: {
  label: string
  value: ReactNode
  copy?: string
}) {
  return (
    <div className="grid grid-cols-[9rem_minmax(0,1fr)] items-start gap-2 py-1.5">
      <dt className="text-xs font-medium text-foreground-secondary">{label}</dt>
      <dd className="flex min-w-0 items-start gap-1.5 text-sm text-foreground">
        <span className="min-w-0 flex-1 break-words">{value}</span>
        {copy ? <CopyButton text={copy} label={`Copy ${label.toLowerCase()}`} /> : null}
      </dd>
    </div>
  )
}

function yesNo(value: boolean): string {
  return value ? 'Yes' : 'No'
}

function availability(value: boolean | null): string {
  if (value === null) return 'Unavailable'
  return value ? 'Available' : 'Not available'
}

function latency(value: number | null): string {
  return value === null ? 'Unavailable' : `${value.toLocaleString()} ms`
}

function RunEvidenceDetail({ row }: { row: PlatformStateBenchRow }) {
  return (
    <div className="flex flex-col gap-5" data-testid="platform-statebench-detail">
      <InlineNotice tone="informational" title="Integrity evidence only">
        This RunBundle passed checksum verification. It is not an authoritative
        performance result, and producer claims are not trusted by this view.
      </InlineNotice>

      <section aria-labelledby="statebench-identities-heading">
        <h2 id="statebench-identities-heading" className="text-sm font-semibold text-foreground">
          Frozen identities
        </h2>
        <dl className="mt-2">
          <FactRow
            label="Bundle digest"
            value={<span className="tnum font-mono text-xs">{row.bundleDigest}</span>}
            copy={row.bundleDigest}
          />
          <FactRow
            label="Run"
            value={<span className="font-mono text-xs">{row.runId}</span>}
            copy={row.runId}
          />
          <FactRow
            label="Application"
            value={<span className="font-mono text-xs">{row.applicationId}</span>}
            copy={row.applicationId}
          />
          <FactRow
            label="Engine"
            value={<span className="font-mono text-xs">{row.engineId}</span>}
            copy={row.engineId}
          />
          <FactRow
            label="Adapter"
            value={<span className="font-mono text-xs">{row.adapterId}</span>}
            copy={row.adapterId}
          />
        </dl>
      </section>

      <section aria-labelledby="statebench-outcomes-heading">
        <h2 id="statebench-outcomes-heading" className="text-sm font-semibold text-foreground">
          Recorded hard outcomes
        </h2>
        <dl className="mt-2">
          <FactRow label="Integrity" value="Verified" />
          <FactRow label="Run status" value={<span className="font-mono text-xs">{row.status}</span>} />
          <FactRow label="Canonical state preserved" value={yesNo(row.statePreserved)} />
          <FactRow label="Capability negotiation accepted" value={yesNo(row.acceptedRun)} />
          <FactRow label="Unauthorized mutations" value={row.unauthorizedMutations.toLocaleString()} />
          <FactRow label="Latency" value={latency(row.latencyMs)} />
          <FactRow label="Usage telemetry" value={availability(row.usageAvailable)} />
          <FactRow label="Bundle files" value={row.bundleFileCount.toLocaleString()} />
          <FactRow label="Authoritative" value="No" />
          <FactRow label="Producer claims trusted" value="No" />
        </dl>
      </section>

      <div className="rounded-sm border border-border">
        <Disclosure title={`Capability degradations (${row.capabilityDegradations.length})`}>
          {row.capabilityDegradations.length > 0 ? (
            <ul className="space-y-1 px-3 pb-3 pt-1 text-sm text-foreground-secondary">
              {row.capabilityDegradations.map((item, index) => (
                <li key={`${item.id}:${item.status ?? ''}:${index}`} className="font-mono text-xs">
                  {item.id}
                  {item.status ? ` · ${item.status}` : ''}
                </li>
              ))}
            </ul>
          ) : (
            <p className="px-3 pb-3 pt-1 text-sm text-foreground-secondary">
              No capability degradations were recorded.
            </p>
          )}
        </Disclosure>
      </div>
    </div>
  )
}

function MatrixTable({
  matrix,
  onInspect,
}: {
  matrix: PlatformStateBenchView
  onInspect: (row: PlatformStateBenchRow) => void
}) {
  if (matrix.rows.length === 0) {
    return (
      <EmptyState
        icon={Database}
        title="No verified RunBundles"
        description="The service returned no path-free verified rows. Rejected or unverified bundles remain excluded."
      />
    )
  }

  return (
    <div className="overflow-x-auto rounded-md border border-border bg-surface">
      <table className="w-full min-w-[860px] text-left text-sm" data-testid="platform-statebench-table">
        <thead className="border-b border-border bg-surface-2 text-xs font-medium text-foreground-secondary">
          <tr>
            <th scope="col" className="px-3 py-2">Run and bundle</th>
            <th scope="col" className="px-3 py-2">Application</th>
            <th scope="col" className="px-3 py-2">Engine and adapter</th>
            <th scope="col" className="px-3 py-2">Recorded outcomes</th>
            <th scope="col" className="w-24 px-3 py-2">
              <span className="sr-only">Inspect</span>
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {matrix.rows.map((row) => (
            <tr key={row.bundleDigest} className="align-top">
              <td className="px-3 py-3">
                <div className="font-mono text-xs text-foreground">{row.runId}</div>
                <div className="mt-1 flex max-w-[20rem] items-start gap-1 text-foreground-tertiary">
                  <span className="min-w-0 truncate font-mono text-xs" title={row.bundleDigest}>
                    {row.bundleDigest}
                  </span>
                  <CopyButton text={row.bundleDigest} label={`Copy bundle digest for ${row.runId}`} />
                </div>
              </td>
              <td className="px-3 py-3 font-mono text-xs text-foreground">{row.applicationId}</td>
              <td className="px-3 py-3">
                <div className="font-mono text-xs text-foreground">{row.engineId}</div>
                <div className="mt-1 font-mono text-xs text-foreground-secondary">{row.adapterId}</div>
              </td>
              <td className="px-3 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge state="success" label="Verified bundle" />
                  <span className="font-mono text-xs text-foreground-secondary">{row.status}</span>
                </div>
                <p className="mt-1 text-xs text-foreground-secondary">
                  State preserved: {yesNo(row.statePreserved)} · degradations:{' '}
                  {row.capabilityDegradations.length} · latency: {latency(row.latencyMs)}
                </p>
                <p className="mt-0.5 text-xs text-foreground-secondary">
                  Unauthorized mutations: {row.unauthorizedMutations.toLocaleString()}
                </p>
              </td>
              <td className="px-3 py-3 text-right">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => onInspect(row)}
                  data-testid={`inspect-statebench-${row.runId}`}
                >
                  <SearchCheck aria-hidden="true" />
                  Inspect
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function PlatformStateBenchPage() {
  const client = getClient()
  const [nonce, setNonce] = useState(0)
  const [result, setResult] = useState<LoadResult | null>(null)
  const [selected, setSelected] = useState<PlatformStateBenchRow | null>(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      let status: LocalServiceStatus
      try {
        status = await client.session.getLocalServiceStatus()
      } catch (error) {
        if (!cancelled) setResult({ key: nonce, status: null, matrix: null, error })
        return
      }
      if (!canInspectPlatformStateBench(status)) {
        if (!cancelled) setResult({ key: nonce, status, matrix: null, error: null })
        return
      }
      try {
        const matrix = await client.platformStateBench.getMatrix(status)
        if (!cancelled) setResult({ key: nonce, status, matrix, error: null })
      } catch (error) {
        if (!cancelled) setResult({ key: nonce, status, matrix: null, error })
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [client, nonce])

  const landed = result?.key === nonce ? result : null
  const operator = landed?.status ? canInspectPlatformStateBench(landed.status) : false
  const matrix = landed?.matrix ?? null

  return (
    <div className="h-full overflow-y-auto bg-app" data-testid="platform-statebench-page">
      <div className="mx-auto flex w-full max-w-[1120px] flex-col gap-4 px-4 py-4">
        <header className="flex flex-wrap items-center gap-2">
          <div>
            <h1 className="text-xl text-foreground">StateBench evidence</h1>
            <p className="mt-0.5 text-sm text-foreground-secondary">
              Path-free verified RunBundle outcomes recorded by this service.
            </p>
          </div>
          <div className="ml-auto flex items-center gap-1">
            <Button asChild size="sm" variant="ghost">
              <Link to="/sources">
                <ArrowLeft aria-hidden="true" />
                Application sources
              </Link>
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setSelected(null)
                setResult(null)
                setNonce((value) => value + 1)
              }}
            >
              <RefreshCw aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </header>

        {!landed ? (
          <SkeletonRows rows={6} />
        ) : landed.error ? (
          <ErrorState
            title={operator ? 'StateBench evidence couldn’t be loaded' : 'Operator access couldn’t be checked'}
            error={landed.error}
            preservedNote="No run, bundle, application, or canonical state was changed."
            onRetry={() => {
              setResult(null)
              setNonce((value) => value + 1)
            }}
          />
        ) : !operator ? (
          <InlineNotice tone="blocked" title="Operator access required">
            This route is reserved for the authenticated platform operator. The
            operator-only StateBench endpoint was not requested, and no
            performance evidence is available to this session.
          </InlineNotice>
        ) : matrix ? (
          <>
            <InlineNotice tone="attention" title="Evidence, not a performance claim">
              {matrix.calibrationMeaning} Only verified bundle integrity and
              recorded hard outcomes are shown; rejected or unverified bundles
              are counted but never exposed as rows.
            </InlineNotice>

            <dl
              className="grid grid-cols-1 divide-y divide-border border-y border-border bg-surface sm:grid-cols-3 sm:divide-x sm:divide-y-0"
              aria-label="Verified and rejected bundle counts"
            >
              <div className="px-3 py-3">
                <dt className="text-xs font-medium text-foreground-secondary">Verified rows</dt>
                <dd className="tnum mt-1 text-2xl text-foreground" data-testid="statebench-verified-count">
                  {matrix.verifiedRowCount.toLocaleString()}
                </dd>
              </div>
              <div className="px-3 py-3">
                <dt className="text-xs font-medium text-foreground-secondary">Rejected or unverified</dt>
                <dd className="tnum mt-1 text-2xl text-foreground" data-testid="statebench-rejected-count">
                  {matrix.rejectedOrUnverifiedCount.toLocaleString()}
                </dd>
              </div>
              <div className="px-3 py-3">
                <dt className="text-xs font-medium text-foreground-secondary">Authority boundary</dt>
                <dd className="mt-1 font-mono text-sm text-foreground" data-testid="statebench-authority-claim">
                  authoritativePerformanceClaim: false
                </dd>
              </div>
            </dl>

            {matrix.truncated ? (
              <InlineNotice tone="informational">
                The verified row set is bounded. {matrix.rows.length.toLocaleString()} of{' '}
                {matrix.verifiedRowCount.toLocaleString()} rows are shown.
              </InlineNotice>
            ) : null}

            <MatrixTable matrix={matrix} onInspect={setSelected} />
          </>
        ) : null}
      </div>

      <Drawer
        open={Boolean(selected)}
        onOpenChange={(open) => {
          if (!open) setSelected(null)
        }}
        title={selected?.runId ?? 'RunBundle evidence'}
        description="Verified hard-outcome facts · platform operator"
        width={600}
      >
        {selected ? <RunEvidenceDetail row={selected} /> : null}
      </Drawer>
    </div>
  )
}
