import { useEffect, useRef, useState } from 'react'
import { ClientError } from '@/client/types'
import {
  OPENCODE_CREDENTIAL_PROVIDER_LABELS,
  OPENCODE_CREDENTIAL_PROVIDERS,
  providerClient,
  type OpenCodeCredentialProvider,
  type ProviderStatus,
} from '@/client/providerClient'
import { InlineNotice } from '@/components'
import { Button } from '@/components/ui/button'
import { useSessionStore } from '@/state'

const MODEL_IDENTIFIER = new RegExp('^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$')

// Honest adoption states, derived from presence only: adopted (with when/where
// it was copied from and the provider names), a source is available, or none.
function adoptionSummary(status: ProviderStatus | null): string {
  if (status?.adoptionStatus === 'adopted') {
    const origin = [
      status.adoptedAt ? `copied ${status.adoptedAt}` : null,
      status.adoptedSource ? `from ${status.adoptedSource}` : null,
    ].filter(Boolean).join(' ')
    const providers = status.adoptedProviders && status.adoptedProviders.length > 0
      ? `; providers: ${status.adoptedProviders.join(', ')}` : ''
    return `Adopted: a copy of an existing OpenCode sign-in is present${origin ? ` (${origin})` : ''}${providers}. Presence only: StatePort does not check that it is still valid, and later changes to the original do not follow the copy.`
  }
  if (status?.adoptionSourceAvailable) {
    const found = status.adoptionSourceProviders && status.adoptionSourceProviders.length > 0
      ? ` Providers found: ${status.adoptionSourceProviders.join(', ')}; only the one matching your saved model (else opencode-go or opencode) is copied.` : ''
    return `Not adopted. An existing OpenCode sign-in file was found in this runtime and can be adopted.${found}`
  }
  return 'Not adopted. No existing OpenCode sign-in file was found in this runtime. Sign in with OpenCode here first, or run the host-side adopt helper (scripts/adopt_opencode_signin.py).'
}

export function ProviderSettings() {
  const service = useSessionStore(state => state.serviceStatus)
  const operator = (service?.state === 'connected' || service?.state === 'degraded')
    && (service.actor?.providerActionsAllowed ?? (service.actor?.role === 'platform_operator' && service.actor.platformOperationsAllowed === true)) === true
  const [status, setStatus] = useState<ProviderStatus | null>(null)
  const [model, setModel] = useState('')
  const [busy, setBusy] = useState(false)
  const draftEdited = useRef(false)
  const requestVersion = useRef(0)
  const [error, setError] = useState<string | null>(null)
  const [verificationResult, setVerificationResult] = useState<ProviderStatus | null>(null)
  const [credentialProvider, setCredentialProvider] = useState<OpenCodeCredentialProvider>('anthropic')
  const [apiKey, setApiKey] = useState('')
  const credentialEdited = useRef(false)
  // A status can still report a provider saved by an older install. Only
  // OpenCode is offered now; saving a model below selects it.
  const otherProviderSaved = status !== null && (status.providerId ?? 'opencode') !== 'opencode'
  const credentialConfigured = status?.credentialStatus === 'configured'
  const signInAdopted = status?.adoptionStatus === 'adopted'
  const modelValid = MODEL_IDENTIFIER.test(model)
  const modelInvalid = model.length > 0 && !modelValid
  const verificationFailed = verificationResult?.requestStatus === 'failed' || verificationResult?.executableStatus === 'missing'
  const verificationPassed = verificationResult !== null && !verificationFailed
    && verificationResult.executableStatus === 'installed' && verificationResult.executableInstalled
  const applyCredentialProvider = (value: ProviderStatus) => {
    if (!credentialEdited.current) setCredentialProvider(value.credentialProvider ?? 'anthropic')
  }
  useEffect(() => {
    let alive = true
    const version = ++requestVersion.current
    providerClient.getStatus().then(value => {
      if (alive && requestVersion.current === version) {
        setStatus(value)
        applyCredentialProvider(value)
        if (!draftEdited.current) setModel(value.model ?? '')
      }
    }).catch(() => { if (alive && requestVersion.current === version) setError('Provider status is unavailable. Check that the local service is running.') })
    return () => { alive = false; requestVersion.current++ }
  }, [])
  async function perform(action: () => Promise<ProviderStatus>, mutation = true, saveDraft = false, verify = false) {
    if (mutation && !operator) {
      setError('Provider changes require an authorized platform operator session. Open StatePort through the operator session, then refresh the page.')
      return
    }
    const version = ++requestVersion.current
    setBusy(true); setError(null); setVerificationResult(null)
    try {
      const value = await action()
      if (requestVersion.current !== version) return
      setStatus(value)
      if (verify) setVerificationResult(value)
      applyCredentialProvider(value)
      if (saveDraft || !draftEdited.current) {
        setModel(value.model ?? '')
        draftEdited.current = false
      }
    }
    catch (failure) {
      if (requestVersion.current !== version) return
      setError(failure instanceof ClientError && (failure.status === 401 || failure.status === 403)
        ? 'The service did not authorize this request. Open StatePort through an authorized platform operator session, then refresh the page. No provider change was confirmed.'
        : saveDraft && failure instanceof ClientError
          ? `Model was not saved: ${failure.message}${failure.code ? ` (${failure.code})` : ''}`
          : 'The provider operation could not be confirmed. Refresh status before retrying; if it remains unavailable, review the service connection in Platform diagnostics.')
    }
    finally { if (requestVersion.current === version) setBusy(false) }
  }
  async function runCredential(action: () => Promise<ProviderStatus>) {
    if (!operator) {
      setError('Provider changes require an authorized platform operator session. Open StatePort through the operator session, then refresh the page.')
      return
    }
    const version = ++requestVersion.current
    setBusy(true); setError(null); setVerificationResult(null)
    try {
      const value = await action()
      if (requestVersion.current !== version) return
      setStatus(value)
      credentialEdited.current = false
      applyCredentialProvider(value)
    }
    catch (failure) {
      if (requestVersion.current !== version) return
      setError(failure instanceof ClientError && (failure.status === 401 || failure.status === 403)
        ? 'The service did not authorize this request. Open StatePort through an authorized platform operator session, then refresh the page. No provider change was confirmed.'
        : 'The provider credential operation could not be confirmed. Refresh status before retrying; if it remains unavailable, review the service connection in Platform diagnostics.')
    }
    finally { if (requestVersion.current === version) setBusy(false) }
  }
  async function runAdoption(action: () => Promise<ProviderStatus>) {
    if (!operator) {
      setError('Provider changes require an authorized platform operator session. Open StatePort through the operator session, then refresh the page.')
      return
    }
    const version = ++requestVersion.current
    setBusy(true); setError(null); setVerificationResult(null)
    try {
      const value = await action()
      if (requestVersion.current !== version) return
      setStatus(value)
    }
    catch (failure) {
      if (requestVersion.current !== version) return
      // A refusal carries a fixed code and a detail that names paths only
      // (never contents), so it is shown as returned.
      setError(failure instanceof ClientError && (failure.status === 401 || failure.status === 403)
        ? 'The service did not authorize this request. Open StatePort through an authorized platform operator session, then refresh the page. No provider change was confirmed.'
        : failure instanceof ClientError && failure.status === 409
          ? `OpenCode sign-in was not adopted: ${failure.message}${failure.code ? ` (${failure.code})` : ''}`
          : 'The sign-in adoption could not be confirmed. Refresh status before retrying; if it remains unavailable, review the service connection in Platform diagnostics.')
    }
    finally { if (requestVersion.current === version) setBusy(false) }
  }
  return <div className="mx-auto h-full w-full min-w-0 max-w-3xl space-y-6 overflow-auto break-words p-4 sm:p-6" aria-labelledby="provider-heading">
    <div><h1 id="provider-heading" className="text-xl font-semibold">Coding provider</h1>
      <p className="mt-2 text-sm text-muted-foreground">Choose the OpenCode model StatePort uses for AI work. Saving a model, having a sign-in or key, and a successful check are separate steps.</p></div>
    {!operator && <p id="provider-permission-help" role="status" className="rounded-md border p-3 text-sm">Provider changes require an authorized platform operator session. Open StatePort through that session, then refresh this page. Status remains available here; opening this page does not grant permission.</p>}
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {otherProviderSaved && <p role="status" className="rounded-md border p-3 text-sm">This installation has a different AI provider saved, and this release does not offer it. Save an OpenCode model below to switch.</p>}
    {status ? <section aria-label="Provider observations" className="space-y-3 rounded-lg border p-4">
      <dl className="grid grid-cols-1 gap-x-3 gap-y-2 text-sm sm:grid-cols-2 [&>dd]:min-w-0 [&>dd]:break-words">
        <dt>Selected provider</dt><dd>{otherProviderSaved ? 'Not available in this release' : 'OpenCode'}</dd>
        <dt>Executable in this runtime</dt><dd>{status.executableStatus === 'unverified' ? 'Not checked in this service session' : status.executableInstalled ? `Installed${status.executableVersion ? ` (${status.executableVersion})` : ''}` : 'Missing'}</dd>
        <dt>Model configuration</dt><dd>{status.configured ? status.model : 'Not configured'}</dd>
        <dt>StatePort connection</dt><dd>{status.connected ? 'Enabled' : 'Disconnected'}</dd>
        <dt>Login presence</dt><dd>{status.authenticationStatus === 'authenticated' ? 'Present (expiry not guaranteed)' : status.authenticationStatus}</dd>
        <dt>Bounded request</dt><dd>{status.requestStatus}</dd>
        <dt>Billing and quota</dt><dd>Unavailable</dd>
      </dl>
      <p role="status" className="text-sm">{status.detail}</p>
    </section> : <p role="status">{error ? 'Provider status is unavailable. Use Refresh status to retry.' : 'Loading provider status…'}</p>}
    <form aria-label="Provider configuration" aria-describedby={!operator ? 'provider-permission-help' : undefined} className="min-w-0 space-y-3" onSubmit={event => { event.preventDefault(); if (modelValid) void perform(() => providerClient.configure(model), true, true) }}>
      <label htmlFor="provider-model" className="block text-sm font-medium">OpenCode model identifier</label>
      <input id="provider-model" value={model} onChange={event => { draftEdited.current = true; setModel(event.target.value) }} autoComplete="off"
        required maxLength={256} disabled={busy || !operator} aria-invalid={modelInvalid || undefined}
        className="min-w-0 w-full rounded-md border bg-background px-3 py-2 text-sm" aria-describedby={modelInvalid ? 'provider-model-help provider-model-error' : 'provider-model-help'} />
      <p id="provider-model-help" className="text-sm text-muted-foreground">Use a model available to your OpenCode runtime. Saving enables new conversation work through the installed OpenCode executable. Connect a provider API key below, or adopt an existing OpenCode sign-in; StatePort never displays or returns a credential.</p>
      {modelInvalid && <p id="provider-model-error" role="alert" className="text-sm text-destructive">Model identifier must start with a letter or digit and contain only letters, digits, and . _ : / + - (up to 256 characters).</p>}
      <Button className="h-auto min-h-10 whitespace-normal" type="submit" disabled={busy || !operator || !modelValid}>Save model and enable</Button>
    </form>
    <section aria-label="OpenCode provider credential" className="space-y-3 rounded-lg border p-4">
      <h2 className="font-medium">OpenCode provider API key</h2>
      <p className="text-sm">Connect one documented provider API key for the OpenCode runtime. StatePort stores it in the private provider home with owner-only permissions, injects it only into managed OpenCode invocations, and never returns it or shows it again.</p>
      <p role="status" className="text-sm">{credentialConfigured
        ? `Credential configured${status?.credentialProvider ? ` for ${OPENCODE_CREDENTIAL_PROVIDER_LABELS[status.credentialProvider]}` : ''}${status?.credentialEnvVar ? ` (${status.credentialEnvVar})` : ''}.`
        : 'No credential.'}</p>
      <form aria-label="OpenCode credential" aria-describedby={!operator ? 'provider-permission-help' : undefined} className="min-w-0 space-y-3"
        onSubmit={event => {
          event.preventDefault()
          const key = apiKey
          if (!key) return
          void runCredential(async () => {
            const value = await providerClient.setCredential(credentialProvider, key)
            setApiKey('')
            return value
          })
        }}>
        <label htmlFor="opencode-credential-provider" className="block text-sm font-medium">OpenCode provider</label>
        <select id="opencode-credential-provider" value={credentialProvider}
          onChange={event => { credentialEdited.current = true; setCredentialProvider(event.target.value as OpenCodeCredentialProvider) }}
          disabled={busy || !operator} className="w-full rounded-md border bg-background px-3 py-2 text-sm">
          {OPENCODE_CREDENTIAL_PROVIDERS.map(id => <option key={id} value={id}>{OPENCODE_CREDENTIAL_PROVIDER_LABELS[id]}</option>)}
        </select>
        <label htmlFor="opencode-api-key" className="block text-sm font-medium">Provider API key</label>
        <input id="opencode-api-key" type="password" value={apiKey} onChange={event => setApiKey(event.target.value)}
          autoComplete="off" maxLength={4096} disabled={busy || !operator}
          className="min-w-0 w-full rounded-md border bg-background px-3 py-2 text-sm" aria-describedby="opencode-api-key-help" />
        <p id="opencode-api-key-help" className="text-sm text-muted-foreground">The key is stored only in the operator-owned provider home and injected into managed OpenCode invocations. It is never returned by the service or shown again; leave the field empty unless you are connecting a new key.</p>
        <div className="flex flex-wrap gap-3">
          <Button className="h-auto min-h-10 whitespace-normal" type="submit" disabled={busy || !operator || !apiKey.trim()}>Connect API key</Button>
          <Button className="h-auto min-h-10 whitespace-normal" type="button" variant="outline" disabled={busy || !operator || !credentialConfigured}
            onClick={() => void runCredential(() => providerClient.removeCredential(credentialProvider))}>Remove credential</Button>
        </div>
      </form>
    </section>
    <section aria-label="Existing OpenCode sign-in" className="space-y-3 rounded-lg border p-4">
      <h2 className="font-medium">Use an existing OpenCode sign-in</h2>
      <p className="text-sm">If OpenCode (including OpenCode Go) is already signed in in this environment, StatePort can take over that sign-in by copying the record of the provider your saved model uses (otherwise opencode-go or opencode) into the private provider home with owner-only permissions. Other providers in the file are never copied. The original is not changed, and the copy is never shown or returned. Caution: an OAuth sign-in rotates its refresh token when it refreshes, so a copied OAuth record can sign the original OpenCode out; prefer an API-key provider such as OpenCode Go.</p>
      <p role="status" aria-label="Adopted sign-in state" className="text-sm">{adoptionSummary(status)}</p>
      <div className="flex flex-wrap gap-3">
        <Button className="h-auto min-h-10 whitespace-normal" type="button" disabled={busy || !operator}
          onClick={() => void runAdoption(providerClient.adoptSignIn)}>Adopt existing OpenCode sign-in</Button>
        <Button className="h-auto min-h-10 whitespace-normal" type="button" variant="outline" disabled={busy || !operator || !signInAdopted}
          onClick={() => void runAdoption(providerClient.removeAdoptedSignIn)}>Remove adopted sign-in</Button>
      </div>
    </section>
    <section className="space-y-3" aria-label="Authentication and verification">
      <div className="flex flex-wrap gap-3">
        <Button className="h-auto min-h-10 whitespace-normal" disabled={busy || !operator || !status?.configured || otherProviderSaved} onClick={() => void perform(providerClient.verify, true, false, true)}>{busy ? 'Working…' : 'Check selected adapter'}</Button>
        <Button className="h-auto min-h-10 whitespace-normal" variant="outline" disabled={busy || !operator || !status?.connected} onClick={() => void perform(providerClient.disconnect)}>Disconnect StatePort</Button>
        <Button className="h-auto min-h-10 whitespace-normal" variant="outline" disabled={busy} onClick={() => void perform(providerClient.getStatus, false)}>Refresh status</Button>
      </div>
      {verificationResult && <section aria-label="Provider check result">
        <InlineNotice
          tone={verificationFailed ? 'danger' : verificationPassed ? 'informational' : 'attention'}
          title={verificationFailed ? 'Adapter check failed' : verificationPassed ? 'Adapter check passed' : 'Adapter check inconclusive'}
        >
          <p>Executable: {verificationResult.executableStatus === 'unverified' ? 'Not checked' : verificationResult.executableInstalled ? 'Installed' : 'Missing'}</p>
          <p>Bounded request: {verificationResult.requestStatus}</p>
          <p>Login presence: {verificationResult.authenticationStatus}</p>
          <p>{verificationResult.detail}</p>
          {verificationResult.executionRefusal && <p>{verificationResult.executionRefusal}</p>}
        </InlineNotice>
      </section>}
    </section>
  </div>
}
