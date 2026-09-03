/**
 * Advanced settings — adapter/build facts as read-only wrapping text, import/
 * export with zod-validated errors, resets (layout, mock data, caches), and
 * mono disclosures for the effective policy and raw capability descriptors.
 * Kept visually last and labeled “Advanced” (settings.md).
 */
import { FlaskConical, PlugZap } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

import type { BuildInfo, GlobalSettings, LocalServiceStatus } from '@/client'
import { ClientError, getClient } from '@/client'
import { MAX_SETTINGS_IMPORT_BYTES } from '@/client/settingsImportPolicy'
import { ConfirmDialog, Disclosure, InlineNotice, copyText } from '@/components'
import { Button } from '@/components/ui/button'
import { localServicePresentation } from '@/semantic'
import { useSessionStore, useWorkspaceStore } from '@/state'

import { ReadOnlyValue, SettingRow, SettingSubsection } from './controls'
import type { GroupProps } from './GlobalGroups'
import { GlobalSettingsHistory } from './GlobalSettingsHistory'
import { ADAPTER_LABELS, CAPABILITY_LABELS, downloadTextFile, scenarioToolsAvailable } from './model'

interface AdvancedProps extends GroupProps {
  replaceAll: (next: GlobalSettings) => void
}

type TestState =
  | { phase: 'idle' }
  | { phase: 'busy' }
  | { phase: 'ok'; status: LocalServiceStatus }
  | { phase: 'error'; message: string }

export function AdvancedGroup({ settings, replaceAll }: AdvancedProps) {
  const pushToast = useSessionStore((s) => s.pushToast)
  const setScenarioLabOpen = useSessionStore((s) => s.setScenarioLabOpen)
  const layouts = useWorkspaceStore((s) => s.layouts)
  const resetLayout = useWorkspaceStore((s) => s.resetLayout)

  const [buildInfo, setBuildInfo] = useState<BuildInfo | null>(null)
  const [test, setTest] = useState<TestState>({ phase: 'idle' })
  const [importText, setImportText] = useState('')
  const [importIssues, setImportIssues] = useState<string[] | null>(null)
  const [importBusy, setImportBusy] = useState(false)
  const [policyJson, setPolicyJson] = useState<string | null>(null)
  const [descriptorJson, setDescriptorJson] = useState<string | null>(null)
  const [confirmResetLayout, setConfirmResetLayout] = useState(false)
  const [confirmResetMock, setConfirmResetMock] = useState(false)
  const [confirmResetSettings, setConfirmResetSettings] = useState(false)
  const [historyRefreshToken, setHistoryRefreshToken] = useState(0)
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  useEffect(() => {
    let cancelled = false
    getClient()
      .session.getBuildInfo()
      .then((info) => {
        if (!cancelled) setBuildInfo(info)
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [])

  const client = getClient()
  const effectiveAdapter = buildInfo?.adapter ?? client.adapter
  const showScenarioTools =
    buildInfo !== null && scenarioToolsAvailable(effectiveAdapter, buildInfo.mode)

  const testConnection = async () => {
    setTest({ phase: 'busy' })
    try {
      const status = await client.session.getLocalServiceStatus()
      setTest({ phase: 'ok', status })
    } catch (err) {
      setTest({ phase: 'error', message: err instanceof Error ? err.message : 'Connection failed' })
    }
  }

  const exportSettings = async () => {
    const json = await client.globalSettings.exportJson()
    downloadTextFile('stateport-settings.json', json)
    pushToast({ kind: 'success', title: 'Settings exported' })
  }

  const runImport = async (json: string) => {
    setImportBusy(true)
    setImportIssues(null)
    try {
      const result = await client.globalSettings.importJson(json)
      replaceAll(result)
      setHistoryRefreshToken((value) => value + 1)
      setImportText('')
      pushToast({ kind: 'success', title: 'Settings imported' })
    } catch (err) {
      if (err instanceof ClientError && err.kind === 'validation') {
        const issues = (err.detail || err.message).split('\n').filter(Boolean)
        setImportIssues(issues.slice(0, 5))
      } else {
        setImportIssues([err instanceof Error ? err.message : 'Import failed'])
      }
    } finally {
      setImportBusy(false)
    }
  }

  const copyDiagnostics = async () => {
    const status = await client.session.getLocalServiceStatus().catch(() => null)
    const snapshot = {
      capturedAt: new Date().toISOString(),
      buildInfo,
      serviceStatus: status,
      activeScenario: useSessionStore.getState().activeScenario,
      diagnosticLogging: settings.privacy.diagnosticLogging,
    }
    const ok = await copyText(JSON.stringify(snapshot, null, 2))
    pushToast(ok ? { kind: 'success', title: 'Diagnostic snapshot copied' } : { kind: 'error', title: 'Could not copy snapshot' })
  }

  const loadPolicy = () => {
    if (policyJson !== null) return
    void client.catalog.list().then((packages) => {
      setPolicyJson(
        JSON.stringify(
          {
            governance: {
              fileWrites: 'governed — every write requires the base revision and produces a receipt',
              destructiveOperations: 'require confirmation; high-risk actions require typed confirmation',
              approvals: 'governed operations run immediately only under an active authorization; otherwise they require approval',
            },
            packages: Object.fromEntries(
              packages.map((entry) => [
                entry.pkg.id,
                {
                  installRequiresApproval: entry.installRequiresApproval,
                  networkPolicy: entry.pkg.networkPolicy,
                  reviewClassification: entry.pkg.reviewClassification,
                },
              ]),
            ),
          },
          null,
          2,
        ),
      )
    })
  }

  const loadDescriptor = () => {
    if (descriptorJson !== null) return
    void client.applications.list().then((instances) => {
      setDescriptorJson(
        JSON.stringify(
          Object.fromEntries(
            instances.map((instance) => [
              instance.id,
              instance.capabilities.map((cap) => ({
                id: cap.id,
                label: CAPABILITY_LABELS[cap.id],
                status: cap.status,
                ...(cap.reason ? { reason: cap.reason } : {}),
              })),
            ]),
          ),
          null,
          2,
        ),
      )
    })
  }

  return (
    <div className="flex flex-col gap-5" data-testid="settings-group-advanced">
      <SettingSubsection title="Service" description="How this build talks to the StatePort service.">
        <SettingRow anchor="adapter-mode" label="Adapter mode" description="The effective adapter in use right now.">
          <ReadOnlyValue
            mono={false}
            value={`${ADAPTER_LABELS[effectiveAdapter]} — the adapter is chosen at startup (VITE_STATEPORT_ADAPTER) and cannot be switched at runtime.`}
            copyValue={effectiveAdapter}
          />
        </SettingRow>
        <SettingRow
          anchor="endpoint"
          label="Service connection"
          description="The effective connection boundary. It is selected when the build starts and cannot be changed from this page."
        >
          <ReadOnlyValue
            value={
              effectiveAdapter === 'http'
                ? `Same origin (${window.location.origin}) — controlled by the running StatePort service.`
                : 'Built-in simulation — no network endpoint is used.'
            }
          />
        </SettingRow>
        <SettingRow anchor="test-connection" label="Test connection" description="Probe the local service now and show the honest result.">
          <Button variant="outline" size="sm" onClick={() => void testConnection()} disabled={test.phase === 'busy'} data-testid="test-connection">
            <PlugZap className="size-3.5" aria-hidden="true" />
            {test.phase === 'busy' ? 'Testing…' : 'Test connection'}
          </Button>
        </SettingRow>
        {test.phase === 'ok' ? (
          <InlineNotice tone={test.status.state === 'connected' ? 'informational' : 'attention'}>
            {localServicePresentation(test.status.state).label} at {test.status.endpoint}
            {test.status.version ? ` — version ${test.status.version}` : ''}
            {test.status.detail ? ` — ${test.status.detail}` : ''}
          </InlineNotice>
        ) : null}
        {test.phase === 'error' ? <InlineNotice tone="danger">{test.message}</InlineNotice> : null}
      </SettingSubsection>

      <SettingSubsection title="Build" description="Exactly what is running.">
        <SettingRow anchor="build-info" label="Build information" description="Version, commit, and build time of this build.">
          {buildInfo ? (
            <dl className="flex flex-col gap-1 text-code" data-testid="build-info">
              {(
                [
                  ['Version', buildInfo.version],
                  ['Commit', buildInfo.commit],
                  ['Built at', buildInfo.builtAt],
                  ['Adapter', ADAPTER_LABELS[buildInfo.adapter]],
                  ['Mode', buildInfo.mode === 'development' ? 'Development' : 'Production'],
                ] as const
              ).map(([label, value]) => (
                <div key={label} className="flex items-baseline gap-2">
                  <dt className="w-20 shrink-0 text-xs text-foreground-secondary">{label}</dt>
                  <dd className="min-w-0 break-all font-mono text-xs text-foreground">{value}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="text-xs text-foreground-secondary">Loading build information…</p>
          )}
        </SettingRow>
        {showScenarioTools ? (
          <SettingRow anchor="scenario-lab" label="Scenario Lab" description="Simulate offline, slow, and failing states. Development builds only.">
            <Button variant="outline" size="sm" onClick={() => setScenarioLabOpen(true)} data-testid="open-scenario-lab">
              <FlaskConical className="size-3.5" aria-hidden="true" />
              Open Scenario Lab
            </Button>
          </SettingRow>
        ) : null}
        <SettingRow anchor="diagnostics" label="Diagnostics" description="Copy a snapshot (build, service status, scenario) for a bug report.">
          <Button variant="outline" size="sm" onClick={() => void copyDiagnostics()}>
            Copy diagnostic snapshot
          </Button>
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Import & export" description="Settings JSON is validated before anything is applied.">
        <SettingRow anchor="export-settings" label="Export settings" description="Download all settings as a JSON file.">
          <Button variant="outline" size="sm" onClick={() => void exportSettings()}>
            Export settings
          </Button>
        </SettingRow>
        <SettingRow anchor="import-settings" label="Import settings" description="Paste a settings export (or choose a file). Invalid files are rejected with row-level errors — nothing is applied.">
          <span className="flex items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept="application/json,.json"
              aria-label="Choose settings file"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (!file) return
                if (file.size > MAX_SETTINGS_IMPORT_BYTES) {
                  setImportText('')
                  setImportIssues([
                    `Settings imports are limited to ${MAX_SETTINGS_IMPORT_BYTES} bytes; this file is ${file.size} bytes.`,
                  ])
                  e.target.value = ''
                  return
                }
                void file.text().then((text) => setImportText(text))
                e.target.value = ''
              }}
            />
            <Button variant="outline" size="sm" onClick={() => fileInputRef.current?.click()}>
              Choose file…
            </Button>
          </span>
        </SettingRow>
        <div className="py-2">
          <label className="flex flex-col gap-1.5">
            <span className="text-xs text-foreground-secondary">Settings JSON</span>
            <textarea
              value={importText}
              onChange={(e) => {
                setImportText(e.target.value)
                setImportIssues(null)
              }}
              rows={4}
              spellCheck={false}
              placeholder='{"general": { … }}'
              className="w-full rounded-sm border border-input bg-surface px-2 py-1.5 font-mono text-code text-foreground outline-none placeholder:text-foreground-tertiary focus-visible:border-focus"
              data-testid="import-settings-text"
            />
          </label>
          <div className="mt-2 flex items-center gap-2">
            <Button size="sm" onClick={() => void runImport(importText)} disabled={importBusy || !importText.trim()} data-testid="import-settings-apply">
              {importBusy ? 'Validating…' : 'Validate & import'}
            </Button>
          </div>
          {importIssues ? (
            <InlineNotice tone="danger" title="Import rejected — nothing was applied" className="mt-2">
              <ul className="list-inside list-disc font-mono text-xs" data-testid="import-issues">
                {importIssues.map((issue) => (
                  <li key={issue}>{issue}</li>
                ))}
              </ul>
            </InlineNotice>
          ) : null}
        </div>
      </SettingSubsection>

      <GlobalSettingsHistory
        replaceAll={replaceAll}
        refreshToken={historyRefreshToken}
      />

      <SettingSubsection title="Resets" description="Each reset tells you exactly what it touches.">
        <SettingRow anchor="reset-layout" label="Reset workspace layouts" description="Return every application’s panel layout to the default preset.">
          <Button variant="outline" size="sm" onClick={() => setConfirmResetLayout(true)}>
            Reset layout
          </Button>
        </SettingRow>
        <SettingRow anchor="clear-caches" label="Clear caches" description="Clear cached UI state (recent palette commands). Settings, layouts, and data are not touched.">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              window.localStorage.removeItem('stateport.commands.v1')
              pushToast({ kind: 'success', title: 'Caches cleared', body: 'Recent palette commands were cleared.' })
            }}
          >
            Clear caches
          </Button>
        </SettingRow>
        <SettingRow anchor="reset-settings" label="Reset settings to defaults" description="Restore every setting on this page to its default value.">
          <Button variant="outline" size="sm" onClick={() => setConfirmResetSettings(true)}>
            Reset settings
          </Button>
        </SettingRow>
        {showScenarioTools ? (
          <SettingRow anchor="reset-mock" label="Reset mock data" description="Wipe all demo applications, conversations, and receipts, then reseed.">
            <Button variant="destructive" size="sm" onClick={() => setConfirmResetMock(true)} data-testid="reset-mock-data">
              Reset mock data
            </Button>
          </SettingRow>
        ) : null}
      </SettingSubsection>

      <SettingSubsection title="Raw truth" description="Evidence, exactly as the client boundary reports it.">
        <div className="flex flex-col gap-2 py-1">
          <Disclosure title="Inspect effective policy">
            <div className="px-2 pb-2 pt-1" id="setting-policy">
              {policyJson === null ? (
                <Button variant="outline" size="sm" onClick={loadPolicy}>
                  Load policy summary
                </Button>
              ) : (
                <pre className="overflow-x-auto rounded-sm border border-border bg-sunken p-2 font-mono text-code text-foreground-secondary">
                  {policyJson}
                </pre>
              )}
            </div>
          </Disclosure>
          <Disclosure title="View raw capability descriptor">
            <div className="px-2 pb-2 pt-1" id="setting-capability-descriptor">
              {descriptorJson === null ? (
                <Button variant="outline" size="sm" onClick={loadDescriptor}>
                  Load descriptor
                </Button>
              ) : (
                <pre className="overflow-x-auto rounded-sm border border-border bg-sunken p-2 font-mono text-code text-foreground-secondary">
                  {descriptorJson}
                </pre>
              )}
            </div>
          </Disclosure>
        </div>
      </SettingSubsection>

      <ConfirmDialog
        open={confirmResetLayout}
        onOpenChange={setConfirmResetLayout}
        title="Reset workspace layouts?"
        description="Every application’s panel sizes, collapsed regions, and presets return to defaults."
        effect={`${Object.keys(layouts).length} application layout${Object.keys(layouts).length === 1 ? '' : 's'} reset.`}
        reversibility="You can rearrange panels again afterwards."
        confirmLabel="Reset layout"
        onConfirm={() => {
          for (const instanceId of Object.keys(layouts)) resetLayout(instanceId)
          pushToast({ kind: 'success', title: 'Layouts reset' })
        }}
      />
      <ConfirmDialog
        open={confirmResetSettings}
        onOpenChange={setConfirmResetSettings}
        title="Reset settings to defaults?"
        description="Every setting on this page returns to its default value."
        reversibility="You can change any setting again afterwards."
        confirmLabel="Reset settings"
        onConfirm={async () => {
          const result = await client.globalSettings.reset()
          replaceAll(result)
          setHistoryRefreshToken((value) => value + 1)
          pushToast({ kind: 'success', title: 'Settings reset to defaults' })
        }}
      />
      {showScenarioTools ? (
        <ConfirmDialog
          open={confirmResetMock}
          onOpenChange={setConfirmResetMock}
          title="Reset mock data?"
          description="All demo applications, conversations, receipts, and settings are wiped and reseeded."
          effect="The built-in demo dataset returns to its initial state."
          reversibility="Not reversible — anything you changed in the demo data is lost."
          confirmLabel="Reset mock data"
          destructive
          requireTypedConfirmation="reset"
          onConfirm={async () => {
            await client.scenario.resetMockState()
            window.location.assign('#/applications')
            window.location.reload()
          }}
        />
      ) : null}
    </div>
  )
}
