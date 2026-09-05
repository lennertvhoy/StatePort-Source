/**
 * Import a local repository (catalog): discover allowlisted candidates,
 * inspect one read-only, review its exact identity and findings, then
 * create an isolated managed copy for supported templates, or register an
 * ordinary repository in place with an explicit approval bound to the
 * inspection digest.
 *
 * The flow never touches repository code: inspection is read-only on the
 * service, and either operation binds the exact inspected identity — a stale
 * digest is rejected by the service and surfaced honestly here.
 */
import { CircleAlert, GitBranch, TriangleAlert } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import type { Receipt, RepositoryCandidate, RepositoryInspection, RepositoryRegistration } from '@/client'
import { ClientError, getClient } from '@/client'
import { Drawer, ErrorState, InlineNotice, Spinner } from '@/components'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { applicationDestinationAvailable } from '@/features/application-experience/registry'

type Stage =
  | { kind: 'loading' }
  | { kind: 'error'; error: ClientError }
  | { kind: 'candidates'; candidates: RepositoryCandidate[] }
  | { kind: 'inspecting'; candidate: RepositoryCandidate }
  | { kind: 'review'; candidate: RepositoryCandidate; inspection: RepositoryInspection }
  | { kind: 'registering'; candidate: RepositoryCandidate; inspection: RepositoryInspection }
  | { kind: 'uncertain'; name: string; reason: string }
  | {
      kind: 'done'
      registration: RepositoryRegistration
      receipt: Receipt
      name: string
      managedCopy: boolean
    }

export function ImportRepositoryDrawer({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate()
  const [stage, setStage] = useState<Stage>({ kind: 'loading' })
  const [name, setName] = useState('')
  const [approved, setApproved] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const candidatesRef = useRef<RepositoryCandidate[]>([])

  const [nonce, setNonce] = useState(0)

  const load = useCallback(() => {
    // Event-handler entry (Retry): reset then retrigger the effect below.
    setStage({ kind: 'loading' })
    setActionError(null)
    setApproved(false)
    setNonce((n) => n + 1)
  }, [])

  useEffect(() => {
    if (!open) return
    let cancelled = false
    getClient()
      .repositoryImport.listLocalCandidates()
      .then((candidates) => {
        if (!cancelled) {
          candidatesRef.current = candidates
          setStage({ kind: 'candidates', candidates })
        }
      })
      .catch((error: unknown) => {
        if (cancelled) return
        setStage({
          kind: 'error',
          error: error instanceof ClientError ? error : new ClientError('network', 'Repository discovery failed'),
        })
      })
    return () => {
      cancelled = true
    }
  }, [open, nonce])

  const inspect = async (candidate: RepositoryCandidate) => {
    setStage({ kind: 'inspecting', candidate })
    setActionError(null)
    try {
      const inspection = await getClient().repositoryImport.inspect(candidate.candidateId)
      setName(candidate.displayName)
      setApproved(false)
      setStage({ kind: 'review', candidate, inspection })
    } catch (error) {
      setActionError(error instanceof ClientError ? error.message : 'Inspection failed')
      setStage({
        kind: 'candidates',
        candidates: candidatesRef.current.length > 0 ? candidatesRef.current : [candidate],
      })
    }
  }

  const importRepository = async () => {
    if (
      stage.kind !== 'review' ||
      !approved ||
      stage.inspection.mutated !== false ||
      stage.inspection.findings.some((finding) => finding.severity === 'error')
    ) return
    const { candidate, inspection } = stage
    setStage({ kind: 'registering', candidate, inspection })
    setActionError(null)
    let registration: RepositoryRegistration
    try {
      const common = {
        candidateId: candidate.candidateId,
        name: name.trim() || inspection.template?.displayName || candidate.displayName,
        approved: true,
      }
      registration = inspection.template
        ? await getClient().repositoryImport.installTemplate({
            ...common,
            inspection,
          })
        : await getClient().repositoryImport.register({
            ...common,
            inspectionDigest: inspection.inspectionDigest,
          })
    } catch (error) {
      setStage({ kind: 'review', candidate, inspection })
      setActionError(
        error instanceof ClientError
          ? `${error.message}${error.detail ? ` — ${error.detail}` : ''}`
          : 'Registration failed',
      )
      return
    }

    const registeredName = name.trim() || candidate.displayName
    if (!registration.receiptId) {
      setStage({
        kind: 'uncertain',
        name: registeredName,
        reason: 'The registration response did not include a receipt ID.',
      })
      return
    }

    try {
      const registeredInstance = await getClient().applications.get(registration.instanceId)
      if (!applicationDestinationAvailable(registeredInstance, 'receipts')) {
        throw new Error('The registered application has no resolved native Receipts route.')
      }
      const receipt = await getClient().receipts.get(registration.receiptId, registration.instanceId)
      if (receipt.id !== registration.receiptId || receipt.instanceId !== registration.instanceId) {
        throw new Error('The durable repository-import receipt did not match the registered application.')
      }
      setStage({
        kind: 'done',
        registration,
        receipt,
        name: registeredName,
        managedCopy: Boolean(inspection.template),
      })
    } catch (error) {
      setStage({
        kind: 'uncertain',
        name: registeredName,
        reason: error instanceof Error ? error.message : 'The durable import receipt could not be reread.',
      })
    }
  }

  const close = (next: boolean) => {
    if (!next) setStage({ kind: 'loading' })
    onOpenChange(next)
  }

  return (
    <Drawer
      open={open}
      onOpenChange={close}
      title="Import a local repository"
      description="Discovery is limited to operator-allowlisted roots. Inspection is read-only — no repository code is executed."
      footer={
        stage.kind === 'review' ? (
          <Button onClick={() => void importRepository()} disabled={!approved} data-testid="import-register">
            {stage.inspection.template ? 'Create isolated copy' : 'Register repository'}
          </Button>
        ) : stage.kind === 'done' ? (
          <>
            <Button variant="secondary" onClick={() => close(false)}>
              Close
            </Button>
            <Button
              onClick={() => {
                close(false)
                if (stage.kind === 'done') navigate(`/app/${stage.registration.instanceId}`)
              }}
              data-testid="import-open-application"
            >
              Open application
            </Button>
          </>
        ) : undefined
      }
    >
      {stage.kind === 'loading' || stage.kind === 'inspecting' || stage.kind === 'registering' ? (
        <div className="flex items-center gap-2 py-6 text-sm text-foreground-secondary">
          <Spinner className="size-4" />
          {stage.kind === 'loading'
            ? 'Discovering allowlisted repositories…'
            : stage.kind === 'inspecting'
              ? 'Inspecting read-only…'
              : 'Registering with exact approval…'}
        </div>
      ) : null}

      {stage.kind === 'error' ? (
        <ErrorState
          title="Repository discovery is unavailable"
          error={stage.error}
          onRetry={() => void load()}
        />
      ) : null}

      {stage.kind === 'candidates' ? (
        <div className="flex flex-col gap-2" data-testid="import-candidates">
          {actionError ? <InlineNotice tone="danger">{actionError}</InlineNotice> : null}
          <InlineNotice tone="informational" title="Prepare a template source">
            For an installed StatePort, place a Git checkout of ProjectState, StudyState, or another supported
            template in <code>/var/lib/stateport/imports</code> inside Ubuntu, then refresh this list. Use the
            installer user to copy the checkout, including its <code>.git</code> directory. StatePort reads this
            folder without modifying it. Custom deployments use their operator-configured source folder.
            Only the reviewed committed snapshot is imported; choose the intended commit before inspection.
          </InlineNotice>
          <Button variant="outline" onClick={load}>Refresh repositories</Button>
          {stage.candidates.length === 0 ? (
            <p className="py-4 text-sm text-foreground-secondary">
              No Git repositories were found in the configured source folders. Prepare a checkout as described
              above, then refresh. A ZIP extraction without Git history cannot establish the required commit identity.
            </p>
          ) : (
            <ul className="flex flex-col gap-1.5">
              {stage.candidates.map((candidate) => (
                <li key={candidate.candidateId}>
                  <button
                    type="button"
                    onClick={() => void inspect(candidate)}
                    className="flex w-full items-center justify-between gap-2 rounded-md border border-border bg-surface px-3 py-2.5 text-left hover:bg-hover"
                    data-testid={`import-candidate-${candidate.displayName}`}
                  >
                    <span className="min-w-0">
                      <span className="block truncate text-sm font-medium text-foreground">{candidate.displayName}</span>
                      <span className="block truncate text-xs text-foreground-tertiary">{candidate.relativeLocation}</span>
                    </span>
                    <GitBranch className="size-4 shrink-0 text-foreground-tertiary" aria-hidden="true" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}

      {stage.kind === 'review' ? (
        <div className="flex flex-col gap-3" data-testid="import-review">
          {actionError ? <InlineNotice tone="danger">{actionError}</InlineNotice> : null}
          <dl className="flex flex-col gap-1.5 text-sm">
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-foreground-secondary">Repository</dt>
              <dd className="min-w-0 truncate text-foreground">{stage.candidate.displayName}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-foreground-secondary">Location</dt>
              <dd className="min-w-0 truncate text-foreground">{stage.inspection.source || stage.candidate.relativeLocation}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-foreground-secondary">Branch</dt>
              <dd className="text-foreground">{stage.inspection.branch}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-foreground-secondary">Commit</dt>
              <dd className="min-w-0 break-all font-mono text-xs text-foreground">{stage.inspection.headCommit || 'unknown'}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-foreground-secondary">Working tree</dt>
              <dd className="text-foreground">{stage.inspection.dirty ? 'Dirty — uncommitted changes present' : 'Clean'}</dd>
            </div>
          </dl>

          {stage.inspection.findings.length > 0 ? (
            <ul className="flex flex-col gap-1" aria-label="Inspection findings">
              {stage.inspection.findings.map((finding) => (
                <li key={finding.code} className="flex items-start gap-1.5 text-xs">
                  {finding.severity === 'error' ? (
                    <CircleAlert className="mt-0.5 size-3.5 shrink-0 text-status-danger" aria-hidden="true" />
                  ) : (
                    <TriangleAlert className="mt-0.5 size-3.5 shrink-0 text-status-attention" aria-hidden="true" />
                  )}
                  <span className="text-foreground-secondary">{finding.message}</span>
                </li>
              ))}
            </ul>
          ) : null}

          {stage.inspection.mutated !== false ? (
            <InlineNotice tone="danger">
              The inspection did not prove that the repository was left unmodified. Import is paused until a
              read-only inspection explicitly reports no mutation.
            </InlineNotice>
          ) : stage.inspection.findings.some((finding) => finding.severity === 'error') ? (
            <InlineNotice tone="danger">
              The inspection reported an error finding — registration must not proceed until it is resolved.
            </InlineNotice>
          ) : (
            <>
              {stage.inspection.template ? (
                <div className="rounded-md border border-border bg-surface-subtle p-3" data-testid="template-adapter-match">
                  <p className="text-sm font-medium text-foreground">
                    {stage.inspection.template.displayName}
                    {stage.inspection.template.declaredVersion
                      ? ` · ${stage.inspection.template.declaredVersion}`
                      : ''}
                  </p>
                  <p className="mt-1 text-xs text-foreground-secondary">
                    {stage.inspection.template.description}
                  </p>
                  <p className="mt-2 text-xs text-foreground-secondary">
                    A committed snapshot will be copied into StatePort-managed storage with its own Git history.
                    The source stays unchanged, uncommitted files are excluded, and only StatePort-owned actions run.
                  </p>
                  <p className="mt-2 font-mono text-xs text-foreground-tertiary">
                    Adapter: {stage.inspection.template.adapterId} · Trusted actions:{' '}
                    {stage.inspection.template.trustedActionIds.length}
                  </p>
                  <p className="mt-2 text-xs text-foreground-secondary">
                    Requested features: {stage.inspection.template.requestedCapabilities.join(', ') || 'none'}.
                    These requests do not grant execution authority. Review the application’s authority and
                    approve the exact action before running work; provider setup is separate.
                  </p>
                </div>
              ) : null}
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-foreground-secondary">Application name</span>
                <input
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  className="h-control rounded-sm border border-input bg-surface px-2 text-sm text-foreground"
                  data-testid="import-name"
                />
              </label>
              <label className="flex items-start gap-2 text-sm" data-testid="import-approval">
                <Checkbox
                  checked={approved}
                  onCheckedChange={(checked) => setApproved(checked === true)}
                  aria-label={
                    stage.inspection.template
                      ? 'Approve creation of an isolated copy of the exact inspected template'
                      : 'Approve registration of the exact inspected repository'
                  }
                />
                <span className="text-foreground-secondary">
                  {stage.inspection.template ? 'Copy' : 'Register'} exactly this inspected repository (commit{' '}
                  {stage.inspection.headCommit.slice(0, 12) || 'unknown'}, digest{' '}
                  {stage.inspection.inspectionDigest.slice(0, 12)}…). If the repository changes, the operation is
                  refused and a fresh inspection is required.
                </span>
              </label>
            </>
          )}
        </div>
      ) : null}

      {stage.kind === 'uncertain' ? (
        <div className="flex flex-col gap-2" data-testid="import-uncertain">
          <InlineNotice tone="danger" title="Import result could not be confirmed">
            {stage.reason} Do not retry this registration from the same review; inspect the Catalog and application
            list before taking further action.
          </InlineNotice>
        </div>
      ) : null}

      {stage.kind === 'done' ? (
        <div className="flex flex-col gap-2" data-testid="import-done">
          <p className="text-sm text-foreground">
            <span className="font-medium">{stage.name}</span>{' '}
            {stage.managedCopy ? (
              <>
                is ready. The source repository itself was never modified; this template runs from an isolated
                StatePort-managed copy.
              </>
            ) : (
              <>is registered in place. StatePort did not modify or take ownership of the repository.</>
            )}
          </p>
          <p className="font-mono text-xs text-foreground-tertiary">
            Repository-import receipt: {stage.receipt.id}
          </p>
          <Button asChild variant="outline" data-testid="import-view-receipt">
            <Link
              to={`/app/${stage.registration.instanceId}/receipts/${stage.receipt.id}${
                stage.receipt.payloadDigest
                  ? `?digest=${encodeURIComponent(stage.receipt.payloadDigest.value)}`
                  : ''
              }`}
            >
              View import receipt
            </Link>
          </Button>
          {stage.registration.receiptId ? (
            <p className="font-mono text-xs text-foreground-tertiary">
              Registration receipt identity: {stage.registration.receiptId}
            </p>
          ) : null}
        </div>
      ) : null}
    </Drawer>
  )
}
