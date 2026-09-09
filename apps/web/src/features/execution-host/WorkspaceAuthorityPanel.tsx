/** Review data only; the separately invoked OS operator issues authority. */
import { useEffect, useRef, useState } from 'react'
import { getClient } from '@/client'
import type { WorkspaceAuthorityPreparation, WorkspaceAuthorityProjection, WorkspaceAuthorityRequest } from '@/client'
import { Button } from '@/components/ui/button'

// Same binary-unit presentation as the execution-host workload limits.
function formatBytes(value: number): string {
  if (value >= 1024 ** 3 && value % 1024 ** 3 === 0) return `${value / 1024 ** 3} GiB`
  if (value >= 1024 ** 2 && value % 1024 ** 2 === 0) return `${value / 1024 ** 2} MiB`
  if (value >= 1024 && value % 1024 === 0) return `${value / 1024} KiB`
  return `${value} bytes`
}
function utcExpiry(value: string): string | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value)) return null
  const canonical = `${value.length === 16 ? `${value}:00` : value}Z`
  const timestamp = Date.parse(canonical)
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === canonical.replace('Z', '.000Z') ? canonical : null
}
function pendingDeadline(request: WorkspaceAuthorityRequest): number | null {
  const requestExpiry = Date.parse(request.expiresAt)
  const grantExpiry = Date.parse(request.grantExpiresAt)
  if (!Number.isFinite(requestExpiry) || !Number.isFinite(grantExpiry)) return null
  const deadline = Math.min(requestExpiry, grantExpiry)
  return deadline > Date.now() ? deadline : null
}

export interface WorkspaceSourceReview {
  reviewDigest: string
  baseRevision: string
  archiveDigest: string
  archiveBytes: number
  fileCount: number
  paths: string[]
}

type Props = { instanceId: string; applicationId: string; sourceReview?: WorkspaceSourceReview; onRefresh: () => void }
export default function WorkspaceAuthorityPanel(props: Props) {
  return <ScopedPanel key={`${props.instanceId}:${props.applicationId}`} {...props} />
}
function ScopedPanel({ instanceId, applicationId, sourceReview, onRefresh }: Props) {
  const client = getClient().executionHost
  const [review, setReview] = useState<WorkspaceAuthorityProjection | null>(null)
  const [prepared, setPrepared] = useState<WorkspaceAuthorityPreparation | null>(null)
  const [expiry, setExpiry] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [, renderExpiry] = useState(0)
  const generation = useRef(0)
  useEffect(() => () => { generation.current += 1 }, [])
  useEffect(() => {
    if (prepared === null) return
    const deadline = pendingDeadline(prepared.request)
    if (deadline === null) return
    // A valid server review lasts 15 minutes; the requested grant may expire sooner.
    const timer = window.setTimeout(() => renderExpiry(value => value + 1), Math.min(deadline - Date.now(), 2_147_483_647))
    return () => window.clearTimeout(timer)
  }, [prepared])
  function pendingMatches(value: WorkspaceAuthorityProjection, pendingRequest: WorkspaceAuthorityPreparation | null): boolean {
    if (!pendingRequest || value.status !== 'available' || !value.issuer) return false
    return pendingDeadline(pendingRequest.request) !== null
      && pendingRequest.request.instanceId === value.instanceId
      && pendingRequest.request.applicationId === value.applicationId
      && pendingRequest.request.catalogIdentityDigest === value.catalogIdentityDigest
      && pendingRequest.request.issuerContextDigest === value.issuer.issuerContextDigest
      && pendingRequest.request.profileDigest === value.issuer.profileDigest
      && pendingRequest.request.sourceMode === value.issuer.sourceMode
      && (value.issuer.sourceMode === 'empty'
        ? pendingRequest.request.formatVersion === 'stateport.workspace-authority-request/v1'
        : pendingRequest.request.formatVersion === 'stateport.workspace-authority-request/v2'
          && pendingRequest.request.source !== undefined
          && typeof pendingRequest.request.sourceDigest === 'string')
  }

  async function refresh(preservePrepared = false) {
    const current = ++generation.current
    const pendingRequest = preservePrepared ? prepared : null
    setBusy(true); setError(null); setReview(null); setExpiry('')
    if (!preservePrepared) setPrepared(null)
    try {
      const value = await client.workspaceAuthority(instanceId)
      if (current !== generation.current) return
      if (value.instanceId !== instanceId || value.applicationId !== applicationId) throw new Error('identity changed')
      setReview(value)
      setPrepared(existing => pendingMatches(value, existing ?? pendingRequest) ? (existing ?? pendingRequest) : null)
      onRefresh()
    } catch {
      if (current === generation.current) {
        if (preservePrepared) setPrepared(null)
        setError('Workspace authority review is unavailable. The prepared request is no longer downloadable until the current operator state is checked again.')
      }
    } finally { if (current === generation.current) setBusy(false) }
  }
  async function prepare() {
    if (!review?.issuer || review.status !== 'available') return
    const grantExpiresAt = utcExpiry(expiry)
    if (grantExpiresAt === null || Date.parse(grantExpiresAt) <= Date.now() || grantExpiresAt > review.issuer.grantExpiresAtLimit) return
    const current = ++generation.current
    setBusy(true); setError(null); setPrepared(null)
    try {
      const request = review.issuer.sourceMode === 'reviewed-commit'
        ? { profileDigest: review.issuer.profileDigest, sourceMode: 'reviewed-commit' as const, grantExpiresAt }
        : { profileDigest: review.issuer.profileDigest, sourceMode: 'empty' as const, grantExpiresAt }
      const result = await client.prepareWorkspaceAuthority(instanceId, request)
      if (current !== generation.current) return
      if (result.request.instanceId !== instanceId || result.request.applicationId !== applicationId
        || result.request.catalogIdentityDigest !== review.catalogIdentityDigest
        || result.request.issuerContextDigest !== review.issuer.issuerContextDigest
        || result.request.profileDigest !== review.issuer.profileDigest || result.request.grantExpiresAt !== grantExpiresAt
        || result.request.sourceMode !== review.issuer.sourceMode
        || (review.issuer.sourceMode === 'empty'
          ? result.request.formatVersion !== 'stateport.workspace-authority-request/v1'
          : result.request.formatVersion !== 'stateport.workspace-authority-request/v2'
            || result.request.source === undefined
            || typeof result.request.sourceDigest !== 'string')) throw new Error('review changed')
      setPrepared(result)
    } catch {
      if (current === generation.current) { setReview(null); setError('The request could not be prepared with the reviewed identity and expiry. Refresh and review again. Preparation does not issue authority.') }
    } finally { if (current === generation.current) setBusy(false) }
  }
  const requestExpired = prepared !== null && pendingDeadline(prepared.request) === null
  const selectedExpiry = utcExpiry(expiry)
  const issuer = review?.issuer
  const pendingValid = prepared !== null && !requestExpired
  return <section aria-label={`Workspace authority ${instanceId}`} className="mt-3 space-y-2 text-sm">
    <div className="flex flex-wrap gap-2">
      <Button size="sm" variant="outline" disabled={busy} onClick={() => void refresh()}>Review workspace authority</Button>
      {prepared && <Button size="sm" variant="outline" disabled={busy} onClick={() => void refresh(true)}>Check operator approval</Button>}
    </div>
    {error && <p role="alert">{error}</p>}
    {review && <>
      <p>Application: {review.displayName} · {review.applicationId} · Instance: {review.instanceId}</p>
      <p className="break-all text-xs">Catalog identity: {review.catalogIdentityDigest}</p>
      {review.refusal && <p role="status">{review.refusal.detail} ({review.refusal.reason})</p>}
      {sourceReview && <section aria-label="Existing seeded workspace binding" className="space-y-1 rounded border border-border p-2">
        <p>Approved source binding: this profile carries reviewed application source for workspace initialization.</p>
        <p>Seed revision: {sourceReview.baseRevision} · {sourceReview.fileCount} files · archive {formatBytes(sourceReview.archiveBytes)}.</p>
        <p className="break-all text-xs">Source review: {sourceReview.reviewDigest} · archive: {sourceReview.archiveDigest}</p>
        <p className="text-xs">{issuer?.sourceMode === 'empty' ? 'This approved source binding is separate from the empty authority request below. ' : ''}This binding is informational until the daemon reports successful creation or recovery. The prepared authority request below carries its own exact source witness when the reviewed committed-source profile is selected.</p>
      </section>}
      {review.issued && <details><summary>{review.issued.status === 'daemon-verified-grant' ? 'Daemon-verified workspace binding' : 'Recorded workspace authority receipt'}</summary><p>{review.issued.status === 'daemon-verified-grant' ? 'Current binding: the daemon verified this exact grant and specification at refresh. This does not attest an operator identity or issuance time; later operations recheck authority.' : 'Issued record; current binding unverified. Historical issuance only; this receipt does not attest an operator identity or current daemon state.'}</p><pre className="overflow-auto text-xs">{JSON.stringify(review.issued, null, 2)}</pre></details>}
      {issuer && <>
        <p>{review.status === 'available' ? (issuer.sourceMode === 'reviewed-commit' ? 'Reviewed committed-source authority request can be prepared. ' : 'Empty workspace authority request can be prepared. ') : (issuer.sourceMode === 'reviewed-commit' ? 'Installed reviewed committed-source profile publication. ' : 'Installed empty profile publication. ')}This publication is a preparation hint. OS operator approval independently rechecks the installed identity. A request grants no authority.</p>
        {issuer.sourceMode === 'empty' ? <p>Source: empty workspace. Application source files are not copied by this profile.</p> : <p>Source: the server will derive the reviewed committed-file witness during preparation. The prepared request will show the exact revision, archive and inventory for explicit OS approval.</p>}
        {issuer.profileId === 'stateport.empty-workspace-terminal/v1' && <section aria-label="Explicit workspace terminal authority" className="space-y-1 rounded border border-border p-2">
          <p>This separate profile authorizes an interactive {issuer.profile.parameters.shell?.join(' ')} PTY inside the isolated workspace, terminal resizing, signals and explicit session closing.</p>
          <p>Reviewed operations: {issuer.operations?.join(', ')}.</p>
          <p>Existing terminal controls apply: 15-minute idle timeout, 1-hour maximum session lifetime, and SIGINT, SIGQUIT or SIGTSTP signals. Workload output bounds are not a total terminal-session output cap.</p>
          <p>This request does not upgrade an existing grant or authorize source seeding.</p>
        </section>}
        <p className="break-all text-xs">Image: {issuer.profile.image.reference}</p>
        <p className="break-all text-xs">Profile: {issuer.profileId} · {issuer.profileDigest}</p>
        <p>Memory {formatBytes(issuer.profile.resources.memoryMaxBytes)} · CPU {issuer.profile.parameters.cpuQuotaPercent}% · PIDs {issuer.profile.resources.pidsMax} · timeout {issuer.profile.timeoutSeconds}s · workload output bound {formatBytes(issuer.profile.outputByteBound)} · network {issuer.profile.parameters.networkMode}.</p>
        <p>Persistent disk request: {formatBytes(issuer.profile.parameters.diskMaxBytes)}. Persistent volume byte quota enforcement is unsupported.</p>
        {review.status === 'available' && <>
          <label className="block">Authority expires at (UTC)<input type="datetime-local" step="1" max={issuer.grantExpiresAtLimit.slice(0, -1)} className="mt-1 block w-full rounded border border-border bg-background p-2" value={expiry} disabled={busy || prepared !== null} onChange={event => setExpiry(event.target.value)} /></label>
          <p>Maximum authority expiry: {issuer.grantExpiresAtLimit}. Request review expires 15 minutes after preparation.</p>
          <Button size="sm" disabled={busy || prepared !== null || selectedExpiry === null || Date.parse(selectedExpiry) <= Date.now() || selectedExpiry > issuer.grantExpiresAtLimit} onClick={() => void prepare()}>Prepare authority request</Button>
        </>}
      </>}
    </>}
    {prepared && <section aria-label="Prepared workspace authority request" className="space-y-2 rounded border border-border p-3">
      <h3 className="font-medium">{pendingValid ? 'Pending operator approval' : 'Prepared request expired'}</h3>
      <p>Prepared only; authority has not been issued by this action.</p>
      {prepared.request.sourceMode === 'reviewed-commit' && <section aria-label="Prepared reviewed source" className="space-y-1 rounded border border-border p-2">
        <p>Prepared reviewed source: revision {prepared.request.source.baseRevision} · source digest {prepared.request.sourceDigest} · {prepared.request.source.sourceInventory.length} committed files.</p>
        <p className="break-all text-xs">Archive {prepared.request.source.sourceArchive.formatVersion} · {formatBytes(prepared.request.source.sourceArchive.archiveBytes)} · {prepared.request.source.sourceArchive.archiveDigest} · context {prepared.request.source.sourceArchive.contextDigest} · descriptor {prepared.request.source.descriptorDigest}.</p>
        <details>
          <summary>Reviewed source inventory ({prepared.request.source.sourceInventory.length} committed files)</summary>
          <pre className="max-h-64 overflow-auto text-xs">{prepared.request.source.sourceInventory.map(entry => `${entry.path} · mode ${entry.mode} · ${entry.contentDigest}`).join('\n')}</pre>
        </details>
        <p>Explicit OS operator approval is still required; only the listed committed files are in scope.</p>
      </section>}
      <p>Authority expiry: {prepared.request.grantExpiresAt} · Request expiry: {prepared.request.expiresAt}</p>
      <p className="break-all text-xs">Request digest: {prepared.request.requestDigest}</p>
      {requestExpired ? <p role="alert">This request has expired. Refresh and prepare a new review.</p> : <>
        <a onClick={event => { if (pendingDeadline(prepared.request) === null) { event.preventDefault(); renderExpiry(value => value + 1) } }} className="underline" download="downloaded-request.json" href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(prepared.request, null, 2) + '\n')}`}>Download authority request</a>
        <p>Review the downloaded request, then explicitly run the installed OS operator helper:</p>
        <pre className="overflow-auto text-xs">{`sudo /usr/local/libexec/stateport-execution-host-provision issue-workspace --request-digest ${prepared.request.requestDigest} < downloaded-request.json`}</pre>
      </>}
      <p>The helper may refuse stale installation or application identity. After operator approval, refresh workspace authority to inspect the recorded issuance and current binding.</p>
    </section>}
  </section>
}
