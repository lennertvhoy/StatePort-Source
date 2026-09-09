import { useEffect, useRef, useState } from 'react'
import { ClientError } from '@/client/types'
import { providerClient, type ProviderStatus } from '@/client/providerClient'
import { Button } from '@/components/ui/button'
import { useSessionStore } from '@/state'

// This temporary shell helper selects the accepted installed runtime; it is
// intentionally not advertised as an installed StatePort executable.
const INSTALLED_CODEX_LOGIN = String.raw`stateport_codex() (
  set -eu
  case "${'$'}{1-}" in
    login) set -- login --device-auth ;;
    logout) set -- logout ;;
    version) set -- --version ;;
    *) printf '%s\n' 'Choose login, logout or version.' >&2; exit 1 ;;
  esac
  control_uid="$(id -u stateport-control)"
  sp_podman() {
    sudo /usr/sbin/runuser -u stateport-control -- /usr/bin/env -i \
      HOME=/var/lib/stateport-control PATH=/usr/bin:/bin LANG=C.UTF-8 \
      XDG_CONFIG_HOME=/var/lib/stateport-control/.config \
      XDG_DATA_HOME=/var/lib/stateport-control/.local/share \
      XDG_RUNTIME_DIR="/run/user/$control_uid" \
      /usr/bin/podman "$@"
  }
  container_output="$(sp_podman ps \
    --filter label=io.stateport.service.id=stateport-web \
    --filter label=io.stateport.profile=accepted \
    --format '{{.ID}}')" || exit 1
  containers=()
  if [ -n "$container_output" ]; then
    mapfile -t containers <<< "$container_output"
  fi
  if [ "${'$'}{#containers[@]}" -ne 1 ]; then
    printf '%s\n' 'Expected exactly one running accepted StatePort web container.' >&2
    exit 1
  fi
  sp_podman exec -it --user 65532:65532 \
    --env CODEX_HOME=/var/lib/stateport-provider/codex \
    --workdir /var/lib/stateport-provider/codex \
    "${'$'}{containers[0]}" /usr/local/bin/codex \
    -c 'cli_auth_credentials_store="file"' "$@"
)
stateport_codex login`

export function ProviderSettings() {
  const service = useSessionStore(state => state.serviceStatus)
  const operator = (service?.state === 'connected' || service?.state === 'degraded')
    && service.actor?.role === 'platform_operator' && service.actor.platformOperationsAllowed === true
  const [status, setStatus] = useState<ProviderStatus | null>(null)
  const [model, setModel] = useState('')
  const [providerId, setProviderId] = useState<'codex' | 'opencode'>('codex')
  const [busy, setBusy] = useState(false)
  const [showLoginCommand, setShowLoginCommand] = useState(false)
  const loginCommandRef = useRef<HTMLPreElement>(null)
  const draftEdited = useRef(false)
  const requestVersion = useRef(0)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let alive = true
    const version = ++requestVersion.current
    providerClient.getStatus().then(value => {
      if (alive && requestVersion.current === version) {
        setStatus(value)
        if (!draftEdited.current) { setModel(value.model ?? ''); setProviderId(value.providerId ?? 'codex') }
      }
    }).catch(() => { if (alive && requestVersion.current === version) setError('Provider status is unavailable. Check that the local service is running.') })
    return () => { alive = false; requestVersion.current++ }
  }, [])
  async function perform(action: () => Promise<ProviderStatus>, mutation = true, saveDraft = false) {
    if (mutation && !operator) {
      setError('Provider changes require an authorized platform operator session. Open StatePort through the operator session, then refresh the page.')
      return
    }
    const version = ++requestVersion.current
    setBusy(true); setError(null)
    try {
      const value = await action()
      if (requestVersion.current !== version) return
      setStatus(value)
      if (saveDraft || !draftEdited.current) {
        setProviderId(value.providerId ?? 'codex'); setModel(value.model ?? '')
        draftEdited.current = false
      }
    }
    catch (failure) {
      if (requestVersion.current !== version) return
      setError(failure instanceof ClientError && (failure.status === 401 || failure.status === 403)
        ? 'The service did not authorize this request. Open StatePort through an authorized platform operator session, then refresh the page. No provider change was confirmed.'
        : 'The provider operation could not be confirmed. Refresh status before retrying; if it remains unavailable, review the service connection in Platform diagnostics.')
    }
    finally { if (requestVersion.current === version) setBusy(false) }
  }
  return <div className="mx-auto h-full w-full min-w-0 max-w-3xl space-y-6 overflow-auto break-words p-4 sm:p-6" aria-labelledby="provider-heading">
    <div><h1 id="provider-heading" className="text-xl font-semibold">Coding provider</h1>
      <p className="mt-2 text-sm text-muted-foreground">Select the coding provider for this StatePort runtime. Configuration, login presence and a successful request are separate checks.</p></div>
    {!operator && <p id="provider-permission-help" role="status" className="rounded-md border p-3 text-sm">Provider changes require an authorized platform operator session. Open StatePort through that session, then refresh this page. Status remains available here; opening this page does not grant permission.</p>}
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {status ? <section aria-label="Provider observations" className="space-y-3 rounded-lg border p-4">
      <dl className="grid grid-cols-1 gap-x-3 gap-y-2 text-sm sm:grid-cols-2 [&>dd]:min-w-0 [&>dd]:break-words">
        <dt>Selected provider</dt><dd>{(status.providerId ?? 'codex') === 'codex' ? 'Codex' : 'OpenCode'}</dd>
        <dt>Executable in this runtime</dt><dd>{status.executableStatus === 'unverified' ? 'Not checked in this service session' : status.executableInstalled ? 'Installed' : 'Missing'}</dd>
        <dt>Model configuration</dt><dd>{status.configured ? status.model : 'Not configured'}</dd>
        <dt>StatePort connection</dt><dd>{status.connected ? 'Enabled' : 'Disconnected'}</dd>
        <dt>Login presence</dt><dd>{status.authenticationStatus === 'authenticated' ? 'Present (expiry not guaranteed)' : status.authenticationStatus}</dd>
        <dt>Bounded request</dt><dd>{status.requestStatus}</dd>
        <dt>Billing and quota</dt><dd>Unavailable</dd>
      </dl>
      <p role="status" className="text-sm">{status.detail}</p>
    </section> : <p role="status">{error ? 'Provider status is unavailable. Use Refresh status to retry.' : 'Loading provider status…'}</p>}
    <form aria-label="Provider configuration" aria-describedby={!operator ? 'provider-permission-help' : undefined} className="min-w-0 space-y-3" onSubmit={event => { event.preventDefault(); void perform(() => providerClient.configure(model.trim(), providerId), true, true) }}>
      <label htmlFor="provider-choice" className="block text-sm font-medium">Coding provider</label>
      <select id="provider-choice" value={providerId} onChange={event => { draftEdited.current = true; setProviderId(event.target.value as 'codex' | 'opencode'); setShowLoginCommand(false) }} disabled={busy || !operator}
        className="w-full rounded-md border bg-background px-3 py-2 text-sm">
        <option value="codex">Codex</option><option value="opencode">OpenCode</option>
      </select>
      <label htmlFor="provider-model" className="block text-sm font-medium">{providerId === 'codex' ? 'Codex' : 'OpenCode'} model identifier</label>
      <input id="provider-model" value={model} onChange={event => { draftEdited.current = true; setModel(event.target.value) }} autoComplete="off"
        required maxLength={256} pattern="[A-Za-z0-9][A-Za-z0-9._:/+\-]*" disabled={busy || !operator}
        className="min-w-0 w-full rounded-md border bg-background px-3 py-2 text-sm" aria-describedby="provider-model-help" />
      <p id="provider-model-help" className="text-sm text-muted-foreground">{providerId === 'codex' ? 'Use a model available to your Codex account. Saving enables new conversation work with this model; it does not authenticate the account.' : 'Saving OpenCode stops current provider work and stores this selection. Execution remains refused until isolated post-agent validation is implemented. No Codex fallback will run.'}</p>
      <Button className="h-auto min-h-10 whitespace-normal" type="submit" disabled={busy || !operator || !model.trim()}>{providerId === 'codex' ? 'Save model and enable' : 'Save provider selection'}</Button>
    </form>
    <section className="space-y-3" aria-label="Authentication and verification">
      {(status?.providerId ?? 'codex') === 'codex' && <div className="space-y-3">
      <h2 className="font-medium">Authenticate through Codex</h2>
      <p className="text-sm">For the supported installation, paste this command into your Ubuntu WSL terminal. It asks for sudo to select the accepted StatePort runtime and runs Codex as its unprivileged service user. The helper exists only in that terminal; it is not an installed command. To check the executable without signing in, replace the final line with stateport_codex version before running the snippet.</p>
      <div className="min-w-0 rounded-md border p-3">
        <Button variant="outline" className="h-auto min-h-10 whitespace-normal" aria-expanded={showLoginCommand} aria-controls="installed-login-command" onClick={() => setShowLoginCommand(value => !value)}>{showLoginCommand ? 'Hide installed login command' : 'Show installed login command'}</Button>
        <div id="installed-login-command" hidden={!showLoginCommand}>
          <Button variant="ghost" className="mt-2" onClick={() => {
            if (!loginCommandRef.current) return
            const range = document.createRange()
            range.selectNodeContents(loginCommandRef.current)
            const selection = window.getSelection()
            selection?.removeAllRanges()
            selection?.addRange(range)
          }}>Select command</Button>
          <p className="text-xs text-muted-foreground">Select the command, then copy it using your browser or keyboard.</p>
          <pre ref={loginCommandRef} aria-label="Installed Codex login command" className="mt-3 max-h-96 select-text overflow-auto whitespace-pre-wrap break-all rounded-md bg-surface p-3 font-mono text-xs"><code>{INSTALLED_CODEX_LOGIN}</code></pre>
        </div>
      </div>
      <p className="text-sm">Open the link printed by Codex in your browser and enter its one-time code. You may first need to enable device code login in your ChatGPT security settings or workspace permissions. Return here to refresh status, then verify a bounded request.</p>
      <p className="text-sm text-muted-foreground">Codex owns and retains the login in a dedicated private directory outside StatePort application backups. Do not paste or upload credentials here, or copy a host login into the container.</p>
      <a className="text-sm underline" href="https://learn.chatgpt.com/docs/auth" target="_blank" rel="noreferrer">Official Codex authentication instructions</a>
      <p className="text-sm text-muted-foreground">Verify sends one short request with no application conversation or files. It may consume account usage. A successful check describes this runtime and moment; it does not establish production qualification.</p>
      </div>}
      <div className="flex flex-wrap gap-3">
        <Button className="h-auto min-h-10 whitespace-normal" disabled={busy || !operator || !status?.configured || ((status.providerId ?? 'codex') === 'codex' && (!status.connected || (status.executableStatus !== 'unverified' && !status.executableInstalled)))} onClick={() => void perform(providerClient.verify)}>{busy ? 'Working…' : status?.providerId === 'opencode' ? 'Check selected adapter' : 'Verify bounded request'}</Button>
        <Button className="h-auto min-h-10 whitespace-normal" variant="outline" disabled={busy || !operator || !status?.connected} onClick={() => void perform(providerClient.disconnect)}>Disconnect StatePort</Button>
        <Button className="h-auto min-h-10 whitespace-normal" variant="outline" disabled={busy} onClick={() => void perform(providerClient.getStatus, false)}>Refresh status</Button>
      </div>
      {(status?.providerId ?? 'codex') === 'codex' && <p className="text-sm text-muted-foreground">Disconnect stops the active assistant processor and cancels queued requests. Reconnecting accepts future messages; your earlier transcript stays intact. To sign out of Codex itself, run <code>stateport_codex logout</code> in the same terminal after defining the helper above. <code>stateport_codex version</code> checks its installed executable without logging in.</p>}
    </section>
  </div>
}
