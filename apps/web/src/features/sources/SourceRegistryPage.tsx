/**
 * Canonical source registry.
 *
 * Every authenticated user receives only the bounded public status projection.
 * Exact authority/candidate evidence and development verification are loaded
 * only after /v1/status identifies the session actor as a platform operator;
 * the service independently enforces both permissions.
 */
import { ArrowLeft, Database, RefreshCw, SearchCheck, ShieldCheck } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import type {
  CanonicalSourceIdentity,
  CanonicalSourceOperatorView,
  CanonicalSourcePublicView,
  CanonicalSourceStatus,
  DevelopmentSourceResolution,
  DevelopmentSourceVerificationInput,
  LocalServiceStatus,
  SemanticState,
} from '@/client'
import { canInspectPlatformStateBench, ClientError, getClient } from '@/client'
import {
  ConfirmDialog,
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

type RegistryResult = {
  key: string
  sources: CanonicalSourcePublicView[]
  status: LocalServiceStatus
  error: unknown
}

type DetailResult = {
  key: string
  detail: CanonicalSourceOperatorView | null
  error: unknown
}

const EMPTY_SOURCES: CanonicalSourcePublicView[] = []

function statusPresentation(status: CanonicalSourceStatus): {
  state: SemanticState
  label: string
} {
  if (status === 'source_available') return { state: 'success', label: 'Verified release available' }
  if (status === 'awaiting_verified_release') return { state: 'waiting', label: 'Awaiting verified release' }
  return { state: 'danger', label: 'Verification unavailable' }
}

function words(value: string | null): string {
  if (!value) return 'None'
  return value.replaceAll('_', ' ')
}

function FactRow({
  label,
  value,
  copy,
}: {
  label: string
  value: React.ReactNode
  copy?: string
}) {
  return (
    <div className="grid grid-cols-[8.5rem_minmax(0,1fr)] items-start gap-2 py-1.5">
      <dt className="text-xs font-medium text-foreground-secondary">{label}</dt>
      <dd className="flex min-w-0 items-start gap-1.5 text-sm text-foreground">
        <span className="min-w-0 flex-1 break-words">{value}</span>
        {copy ? <CopyButton text={copy} label={`Copy ${label.toLowerCase()}`} /> : null}
      </dd>
    </div>
  )
}

function IdentityFacts({ identity }: { identity: CanonicalSourceIdentity }) {
  return (
    <dl className="mt-1">
      <FactRow label="Repository" value={<span className="font-mono text-xs">{identity.repository}</span>} copy={identity.repository} />
      <FactRow label="Commit" value={<span className="tnum font-mono text-xs">{identity.commit}</span>} copy={identity.commit} />
      <FactRow label="Tree" value={<span className="tnum font-mono text-xs">{identity.tree}</span>} copy={identity.tree} />
      <FactRow
        label="Manifest digest"
        value={<span className="tnum font-mono text-xs">{identity.manifestDigest}</span>}
        copy={identity.manifestDigest}
      />
      <FactRow
        label="Source digest"
        value={<span className="tnum font-mono text-xs">{identity.sourceDigest}</span>}
        copy={identity.sourceDigest}
      />
    </dl>
  )
}

function EvidenceList({ title, items }: { title: string; items: string[] }) {
  return (
    <Disclosure title={`${title} (${items.length})`} className="border-t border-border">
      {items.length > 0 ? (
        <ul className="space-y-1 px-3 pb-3 pt-1 text-xs text-foreground-secondary">
          {items.map((item) => (
            <li key={item} className="font-mono">
              {item}
            </li>
          ))}
        </ul>
      ) : (
        <p className="px-3 pb-3 pt-1 text-sm text-foreground-secondary">No evidence is recorded.</p>
      )}
    </Disclosure>
  )
}

function OperatorSourceDetail({
  publicSource,
  detail,
  verification,
  verificationError,
}: {
  publicSource: CanonicalSourcePublicView
  detail: CanonicalSourceOperatorView
  verification: DevelopmentSourceResolution | null
  verificationError: unknown
}) {
  const canonical = detail.canonicalRelease
  const candidate = detail.developmentCandidate
  const status = statusPresentation(canonical.status)

  return (
    <div className="flex flex-col gap-5" data-testid="source-operator-detail">
      <InlineNotice tone={canonical.installable ? 'informational' : 'attention'}>
        {detail.message} Candidate evidence never substitutes for a canonical release.
      </InlineNotice>

      <section aria-labelledby="canonical-release-heading">
        <div className="flex flex-wrap items-center gap-2">
          <h2 id="canonical-release-heading" className="text-sm font-semibold text-foreground">
            Canonical release
          </h2>
          <StatusBadge state={status.state} label={status.label} />
        </div>
        <dl className="mt-2">
          <FactRow label="Source class" value="Canonical release" />
          <FactRow label="Trust" value={words(canonical.trust)} />
          <FactRow label="Production install" value={canonical.installable ? 'Allowed' : 'Not allowed'} />
          <FactRow label="Missing requirement" value={words(canonical.missingRequirement)} />
        </dl>
        {canonical.identity ? (
          <IdentityFacts identity={canonical.identity} />
        ) : (
          <p className="mt-2 text-sm text-foreground-secondary">No immutable canonical release identity is recorded.</p>
        )}
        <div className="mt-2 rounded-sm border border-border">
          <EvidenceList title="Required modules" items={canonical.requiredModules} />
          <EvidenceList title="Expected self-tests" items={canonical.expectedSelfTests} />
        </div>
      </section>

      <section aria-labelledby="authority-heading">
        <h2 id="authority-heading" className="text-sm font-semibold text-foreground">
          Source authority
        </h2>
        <dl className="mt-2">
          <FactRow
            label="Repository"
            value={<span className="font-mono text-xs">{detail.authority.repository}</span>}
            copy={detail.authority.repository}
          />
          <FactRow label="Ref policy" value={words(detail.authority.canonicalRefPolicy)} />
          <FactRow
            label="Manifest"
            value={<span className="font-mono text-xs">{detail.authority.manifestPath}</span>}
            copy={detail.authority.manifestPath}
          />
          <FactRow
            label="Contract"
            value={<span className="font-mono text-xs">{detail.authority.manifestContract}</span>}
            copy={detail.authority.manifestContract}
          />
        </dl>
      </section>

      {candidate ? (
        <section aria-labelledby="candidate-heading" data-testid="development-candidate">
          <div className="flex flex-wrap items-center gap-2">
            <h2 id="candidate-heading" className="text-sm font-semibold text-foreground">
              Development candidate
            </h2>
            <StatusBadge state="attention" label="Not a release" />
          </div>
          <p className="mt-1 text-sm text-foreground-secondary">
            This exact identity is eligible only for isolated development verification. It cannot install or update a
            production application.
          </p>
          <dl className="mt-2">
            <FactRow label="Testing allowed" value={candidate.testingAllowed ? 'Yes' : 'No'} />
            <FactRow label="Production install" value="Not allowed" />
          </dl>
          <IdentityFacts identity={candidate.identity} />
          <div className="mt-2 rounded-sm border border-border">
            <EvidenceList title="Verified modules" items={candidate.verifiedModules} />
            <EvidenceList title="Recorded self-tests" items={candidate.verifiedSelfTests} />
          </div>
          <p className="mt-2 text-xs text-foreground-tertiary">
            These are recorded descriptor claims. The inspection view does not execute repository code.
          </p>
        </section>
      ) : (
        <InlineNotice tone="informational">No development candidate is recorded for this source.</InlineNotice>
      )}

      {verification ? (
        <InlineNotice tone="informational" title="Development verification recorded">
          <p>
            The exact candidate was verified for isolated development use. Production install remains unavailable.
          </p>
          <dl className="mt-2">
            <FactRow label="Verified at" value={verification.verifiedAt} />
            <FactRow
              label="Receipt digest"
              value={<span className="tnum font-mono text-xs">{verification.receiptDigest}</span>}
              copy={verification.receiptDigest}
            />
            <FactRow
              label="Tests run now"
              value={verification.selfTestsExecutedByThisOperation ? 'Yes' : 'No — declarations were matched only'}
            />
          </dl>
        </InlineNotice>
      ) : null}

      {verificationError ? (
        <InlineNotice tone="danger" title="Development verification failed">
          {verificationError instanceof Error ? verificationError.message : 'The service refused the verification.'}
        </InlineNotice>
      ) : null}

      <p className="sr-only">{publicSource.publicName}</p>
    </div>
  )
}

export default function SourceRegistryPage() {
  const client = getClient()
  const navigate = useNavigate()
  const { sourceId: selectedSourceId } = useParams<{ sourceId: string }>()
  const [nonce, setNonce] = useState(0)
  const [detailNonce, setDetailNonce] = useState(0)
  const [registryResult, setRegistryResult] = useState<RegistryResult | null>(null)
  const [detailResult, setDetailResult] = useState<DetailResult | null>(null)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [verification, setVerification] = useState<DevelopmentSourceResolution | null>(null)
  const [verificationError, setVerificationError] = useState<unknown>(null)

  const registryKey = `${nonce}`
  useEffect(() => {
    let cancelled = false
    Promise.all([client.sources.list(), client.session.getLocalServiceStatus()])
      .then(([sources, status]) => {
        if (!cancelled) setRegistryResult({ key: registryKey, sources, status, error: null })
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setRegistryResult({
            key: registryKey,
            sources: [],
            status: { state: 'unknown', endpoint: '/v1/status' },
            error,
          })
        }
      })
    return () => {
      cancelled = true
    }
  }, [client, nonce, registryKey])

  const landedRegistry = registryResult?.key === registryKey ? registryResult : null
  const sources = landedRegistry?.sources ?? EMPTY_SOURCES
  const operator = landedRegistry?.status.actor?.role === 'platform_operator'
  const statebenchOperator = landedRegistry?.status
    ? canInspectPlatformStateBench(landedRegistry.status)
    : false
  const selectedPublicSource = useMemo(
    () => sources.find((source) => source.sourceId === selectedSourceId) ?? null,
    [selectedSourceId, sources],
  )

  const detailKey = `${selectedSourceId ?? ''}#${detailNonce}`
  useEffect(() => {
    if (!operator || !selectedPublicSource) return
    let cancelled = false
    client.sources
      .getOperatorDetail(selectedPublicSource.sourceId)
      .then((detail) => {
        if (!cancelled) setDetailResult({ key: detailKey, detail, error: null })
      })
      .catch((error: unknown) => {
        if (!cancelled) setDetailResult({ key: detailKey, detail: null, error })
      })
    return () => {
      cancelled = true
    }
  }, [client, detailKey, operator, selectedPublicSource])

  const landedDetail = detailResult?.key === detailKey ? detailResult : null
  const detailLoading = Boolean(operator && selectedPublicSource && !landedDetail)
  const detail = landedDetail?.detail ?? null
  const candidate = detail?.developmentCandidate ?? null

  const closeDetail = useCallback(() => {
    setConfirmOpen(false)
    setVerification(null)
    setVerificationError(null)
    void navigate('/sources', { replace: true })
  }, [navigate])

  const verificationInput: DevelopmentSourceVerificationInput | null = candidate
    ? {
        sourceId: detail!.sourceId,
        sourceClass: candidate.sourceClass,
        expectedCommit: candidate.identity.commit,
        expectedTree: candidate.identity.tree,
        expectedManifestDigest: candidate.identity.manifestDigest,
        expectedSourceDigest: candidate.identity.sourceDigest,
        acknowledgement: candidate.verificationAction.acknowledgement,
      }
    : null

  const verify = async () => {
    if (!verificationInput) return
    setVerificationError(null)
    try {
      const result = await client.sources.verifyDevelopmentCandidate(verificationInput)
      setVerification(result)
    } catch (error) {
      setVerificationError(error)
      if (error instanceof ClientError && error.status === 409) {
        setDetailNonce((value) => value + 1)
      }
    }
  }

  if (!landedRegistry) {
    return (
      <div className="h-full overflow-y-auto bg-app p-4" data-testid="source-registry-page">
        <div className="mx-auto w-full max-w-[960px]">
          <SkeletonRows rows={5} />
        </div>
      </div>
    )
  }

  if (landedRegistry.error) {
    return (
      <div className="flex h-full items-center justify-center bg-app p-6" data-testid="source-registry-page">
        <ErrorState
          title="Source status couldn’t be loaded"
          error={landedRegistry.error}
          preservedNote="No source, release, or application state was changed."
          onRetry={() => setNonce((value) => value + 1)}
        />
      </div>
    )
  }

  return (
    <div className="h-full overflow-y-auto bg-app" data-testid="source-registry-page">
      <div className="mx-auto flex w-full max-w-[960px] flex-col gap-4 px-4 py-4">
        <header className="flex flex-wrap items-center gap-2">
          <div>
            <h1 className="text-xl text-foreground">Application sources</h1>
            <p className="mt-0.5 text-sm text-foreground-secondary">
              Canonical release status for packages known to this StatePort service.
            </p>
          </div>
          <div className="ml-auto flex items-center gap-1">
            {statebenchOperator ? (
              <Button asChild size="sm" variant="ghost">
                <Link to="/statebench" data-testid="open-platform-statebench">
                  <SearchCheck aria-hidden="true" />
                  StateBench evidence
                </Link>
              </Button>
            ) : null}
            <Button asChild size="sm" variant="ghost">
              <Link to="/catalog">
                <ArrowLeft aria-hidden="true" />
                Catalog
              </Link>
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setNonce((value) => value + 1)}>
              <RefreshCw aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </header>

        {client.adapter === 'mock' ? (
          <InlineNotice tone="informational">
            Scenario data is shown. Production uses the HTTP source registry and never falls back to this mock.
          </InlineNotice>
        ) : null}

        {selectedSourceId && !operator ? (
          <InlineNotice tone="blocked" title="Operator access required">
            Exact repository and candidate evidence is available only to the authenticated platform operator. Public
            release status remains visible below.
          </InlineNotice>
        ) : null}

        {selectedSourceId && operator && !selectedPublicSource ? (
          <InlineNotice tone="danger" title="Source not found">
            The selected identity is not present in the bounded source registry.
          </InlineNotice>
        ) : null}

        {sources.length === 0 ? (
          <EmptyState
            icon={Database}
            title="No application sources"
            description="The connected service did not report any canonical application-source records."
          />
        ) : (
          <ul className="divide-y divide-border rounded-md border border-border bg-surface" data-testid="source-list">
            {sources.map((source) => {
              const presentation = statusPresentation(source.status)
              return (
                <li key={source.sourceId} className="flex flex-wrap items-center gap-3 px-3 py-3">
                  <div className="flex size-9 shrink-0 items-center justify-center rounded-sm bg-surface-2 text-foreground-secondary">
                    <Database className="size-4" aria-hidden="true" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="font-medium text-foreground">{source.publicName}</h2>
                      <StatusBadge state={presentation.state} label={presentation.label} />
                    </div>
                    <p className="mt-0.5 text-sm text-foreground-secondary">{source.message}</p>
                    <p className="mt-1 text-xs text-foreground-tertiary">
                      Production install: {source.installable ? 'available' : 'unavailable'}
                    </p>
                  </div>
                  {operator ? (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => void navigate(`/sources/${source.sourceId}`)}
                      data-testid={`inspect-source-${source.sourceId}`}
                    >
                      <SearchCheck aria-hidden="true" />
                      Inspect provenance
                    </Button>
                  ) : null}
                </li>
              )
            })}
          </ul>
        )}

        <p className="text-xs text-foreground-tertiary">
          A development candidate can provide isolated-test evidence. It cannot become a canonical release or enable a
          production install through this surface.
        </p>
      </div>

      <Drawer
        open={Boolean(operator && selectedPublicSource)}
        onOpenChange={(open) => {
          if (!open) closeDetail()
        }}
        title={selectedPublicSource?.publicName ?? 'Source provenance'}
        description="Exact redacted source evidence · platform operator"
        width={560}
        footer={
          detail && candidate ? (
            <Button
              onClick={() => setConfirmOpen(true)}
              disabled={!candidate.verificationAction.enabled || Boolean(verification)}
              data-testid="verify-development-candidate"
            >
              <ShieldCheck aria-hidden="true" />
              {verification ? 'Verification recorded' : 'Verify for development'}
            </Button>
          ) : undefined
        }
      >
        {detailLoading ? <SkeletonRows rows={6} /> : null}
        {landedDetail?.error ? (
          <ErrorState
            title="Source provenance couldn’t be loaded"
            error={landedDetail.error}
            preservedNote="No source or application state was changed."
            onRetry={() => setDetailNonce((value) => value + 1)}
          />
        ) : null}
        {detail && selectedPublicSource ? (
          <OperatorSourceDetail
            publicSource={selectedPublicSource}
            detail={detail}
            verification={verification}
            verificationError={verificationError}
          />
        ) : null}
      </Drawer>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="Verify development candidate"
        description="Verify the exact inspected candidate for isolated development use."
        target={candidate ? `${detail?.sourceId} @ ${candidate.identity.commit}` : undefined}
        effect="Resolve and inspect this immutable candidate, record verification evidence, and keep production installation disabled."
        reversibility="This does not publish a release or mutate canonical application state. The verification record is retained."
        confirmLabel="Verify exact candidate"
        onConfirm={verify}
      />
    </div>
  )
}
