/**
 * Application-scoped settings (`#/app/:instanceId/settings`) — instance name,
 * per-app notification override, capability list with honest reasons, and the
 * app-scoped settings from client.appSettings. Same dirty-bar model as the
 * global surface; group navigation lives in the `?group=` search param.
 */
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import type { ApplicationPackage, AppSettings, TerminalTarget } from '@/client'
import { getClient } from '@/client'
import { CapabilityDot, ConfirmDialog, Disclosure, ErrorState, InlineNotice, SkeletonRows, StatusBadge } from '@/components'
import { Button } from '@/components/ui/button'
import { capabilityPresentation } from '@/semantic'
import { useSessionStore } from '@/state'
import { useCurrentInstance } from '@/shell/currentInstance'
import { useMediaQuery } from '@/shell/platform'
import { cn } from '@/lib/utils'

import {
  CheckboxChips,
  NumberControl,
  ReadOnlyValue,
  SelectControl,
  SettingRow,
  SettingSubsection,
  TextControl,
  ToggleControl,
} from './controls'
import { ContextLifecycleGroup } from './ContextLifecycleGroup'
import { RecoveryRestorePanel } from './RecoveryRestorePanel'
import {
  APP_NOTIFICATION_LEVEL_LABELS,
  CAPABILITY_LABELS,
  CONTEXT_CHIP_LABELS,
  RECOVERY_STATE_LABELS,
  deepEqual,
  setPaths,
} from './model'

interface AppGroupMeta {
  id: string
  label: string
  description: string
  advanced?: boolean
}

const APP_GROUPS: readonly AppGroupMeta[] = [
  { id: 'general', label: 'General', description: 'Instance name and identity.' },
  { id: 'capabilities', label: 'Permissions & capabilities', description: 'What this application can do — and why some things are unavailable.' },
  { id: 'conversation', label: 'Conversation', description: 'Default context for this application’s conversations.' },
  {
    id: 'context',
    label: 'Context lifecycle',
    description: 'Effective policy, continuity identities, compaction, and provider handoff.',
  },
  { id: 'notifications', label: 'Notifications', description: 'Notification level for this application.' },
  { id: 'backup', label: 'Backup & recovery', description: 'Backup schedule and current state.' },
  { id: 'advanced', label: 'Advanced', description: 'Identifiers, raw descriptor, and reset.', advanced: true },
]

type AppGroupId = (typeof APP_GROUPS)[number]['id']

function isAppGroupId(value: string | null): value is AppGroupId {
  return Boolean(value) && APP_GROUPS.some((g) => g.id === value)
}

const chipOptions = (Object.entries(CONTEXT_CHIP_LABELS) as [keyof typeof CONTEXT_CHIP_LABELS, string][]).map(
  ([value, label]) => ({ value, label }),
)

export function AppSettingsView({ instanceId }: { instanceId: string }) {
  const { instance, loading: instanceLoading, error: instanceError, refresh } = useCurrentInstance()
  const isMobile = useMediaQuery('(max-width: 767px)')
  const pushToast = useSessionStore((s) => s.pushToast)
  const client = getClient()
  const isMock = client.adapter === 'mock'
  const [params, setParams] = useSearchParams()

  const [saved, setSaved] = useState<AppSettings | null>(null)
  const [draft, setDraft] = useState<AppSettings | null>(null)
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<unknown>(null)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [nonce, setNonce] = useState(0)
  const [pkg, setPkg] = useState<ApplicationPackage | null>(null)
  const [targets, setTargets] = useState<TerminalTarget[]>([])
  const [confirmReset, setConfirmReset] = useState(false)
  /** 'list' = the mobile group list (no ?group=). */
  const [pendingGroup, setPendingGroup] = useState<AppGroupId | 'list' | null>(null)

  const activeGroup: AppGroupId | null = isAppGroupId(params.get('group')) ? (params.get('group') as AppGroupId) : null

  // Desktop without ?group=: land on General (mobile shows the group list).
  useEffect(() => {
    if (!isMobile && !isAppGroupId(params.get('group'))) {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev)
          next.set('group', 'general')
          return next
        },
        { replace: true },
      )
    }
  }, [isMobile, params, setParams])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setLoadError(null)
    getClient()
      .appSettings.get(instanceId)
      .then((settings) => {
        if (cancelled) return
        setSaved(settings)
        setDraft(settings)
        setLoading(false)
      })
      .catch((err) => {
        if (!cancelled) {
          setLoadError(err)
          setLoading(false)
        }
      })
    return () => {
      cancelled = true
    }
  }, [instanceId, nonce])

  useEffect(() => {
    setName(instance?.name ?? '')
  }, [instance?.name])

  useEffect(() => {
    let cancelled = false
    if (!instance) return
    getClient()
      .catalog.get(instance.packageId)
      .then((p) => {
        if (!cancelled) setPkg(p.pkg)
      })
      .catch(() => undefined)
    getClient()
      .terminal.listTargets(instance.id)
      .then((list) => {
        if (!cancelled) setTargets(list)
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [instance])

  const dirty = useMemo(() => {
    if (!saved || !draft || !instance) return false
    return !deepEqual(saved, draft) || (isMock && name.trim() !== instance.name)
  }, [saved, draft, name, instance, isMock])

  const set = useCallback((...entries: readonly (readonly [string, unknown])[]) => {
    setDraft((current) => (current ? setPaths(current, entries) : current))
    setSaveError(null)
  }, [])

  const save = useCallback(async () => {
    if (!draft || !instance || saving) return
    const trimmed = name.trim()
    setSaving(true)
    setSaveError(null)
    try {
      if (isMock && trimmed && trimmed !== instance.name) {
        await client.applications.rename(instanceId, trimmed)
      }
      const patch = {
        notificationLevel: draft.notificationLevel,
        conversation: { defaultContext: draft.conversation.defaultContext },
        backup: { enabled: draft.backup.enabled, intervalHours: draft.backup.intervalHours },
        terminal: { defaultTargetId: draft.terminal.defaultTargetId || undefined },
      }
      const result = await client.appSettings.update(instanceId, patch)
      setSaved(result)
      setDraft(result)
      refresh()
      pushToast({
        kind: 'success',
        title: isMock ? 'Application settings saved' : 'Browser preferences saved',
        body: isMock
          ? undefined
          : 'These presentation preferences remain on this device and do not change canonical application state.',
      })
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setSaving(false)
    }
  }, [client, draft, instance, instanceId, isMock, name, saving, refresh, pushToast])

  const discard = useCallback(() => {
    setDraft(saved)
    setName(instance?.name ?? '')
    setSaveError(null)
  }, [saved, instance])

  const goGroup = (id: AppGroupId | null) => {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        if (id) next.set('group', id)
        else next.delete('group')
        return next
      },
      { replace: false },
    )
  }

  const requestGroup = (id: AppGroupId | null) => {
    if (dirty && id !== activeGroup) setPendingGroup(id === null ? 'list' : id)
    else goGroup(id)
  }

  // ── Loading / error ────────────────────────────────────────────────────────
  if (instanceLoading || loading) {
    return (
      <div className="h-full bg-app p-6" data-testid="settings-stub">
        <SkeletonRows rows={8} />
      </div>
    )
  }
  if (instanceError || loadError || !instance || !draft) {
    return (
      <div className="h-full bg-app" data-testid="settings-stub">
        <ErrorState
          title="Application settings couldn’t be loaded"
          error={instanceError ?? loadError}
          preservedNote="Nothing was changed."
          onRetry={() => {
            refresh()
            setNonce((n) => n + 1)
          }}
        />
      </div>
    )
  }

  const activeMeta = APP_GROUPS.find((g) => g.id === activeGroup) ?? null

  const groupNav = (vertical: boolean) => (
    <nav aria-label="Application settings groups" className={cn(vertical ? 'flex flex-col gap-0.5' : 'flex gap-1 overflow-x-auto pb-1')}>
      {APP_GROUPS.map((g) => {
        const active = activeGroup === g.id
        return (
          <button
            key={g.id}
            type="button"
            onClick={() => requestGroup(g.id)}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'rounded-sm text-left text-sm outline-none transition-colors duration-instant focus-visible:ring-2 focus-visible:ring-focus',
              vertical ? 'min-h-nav-row px-2 py-1' : 'min-h-control-sm shrink-0 whitespace-nowrap px-2.5',
              g.advanced && vertical ? 'mt-2 border-t border-border pt-2' : '',
              active ? 'bg-active font-medium text-foreground' : 'text-foreground-secondary hover:bg-hover hover:text-foreground',
            )}
          >
            {g.label}
          </button>
        )
      })}
    </nav>
  )

  const saveBar = dirty ? (
    <div
      className="sticky bottom-0 z-10 mt-4 border-t border-border bg-surface/95 px-4 pb-[max(0.75rem,env(safe-area-inset-bottom))] pt-3 backdrop-blur-sm"
      role="region"
      aria-label={isMock ? 'Unsaved application settings changes' : 'Unsaved browser preferences'}
      data-testid="settings-save-bar"
    >
      <div className="mx-auto flex max-w-[760px] flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium text-foreground">
            {isMock ? 'Unsaved changes' : 'Unsaved browser preferences'}
          </p>
          {saveError ? (
            <p className="text-xs text-status-danger" role="alert">
              Couldn’t save — your changes are still here. {saveError}
            </p>
          ) : (
            <p className="text-xs text-foreground-secondary">
              {isMock
                ? 'Save to apply, or discard to revert.'
                : 'Save on this device, or discard. Canonical application state is unchanged.'}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={discard} disabled={saving}>
            Discard
          </Button>
          <Button size="sm" onClick={() => void save()} disabled={saving || !name.trim()} data-testid="app-settings-save">
            {saving ? 'Saving…' : saveError ? 'Retry save' : isMock ? 'Save' : 'Save locally'}
          </Button>
        </div>
      </div>
    </div>
  ) : null

  const content = () => {
    switch (activeGroup) {
      case 'general':
        return (
          <div className="flex flex-col gap-5" data-testid="app-settings-general">
            <SettingSubsection title="Identity">
              <SettingRow anchor="app-name" label="Instance name" description="The primary name for this application everywhere in StatePort.">
                {isMock ? (
                  <TextControl value={name} onChange={setName} className="w-64" />
                ) : (
                  <ReadOnlyValue
                    mono={false}
                    value={`${instance.name} — fixed at registration; the connected service does not expose rename.`}
                  />
                )}
              </SettingRow>
              <SettingRow anchor="app-package" label="Package" description="The package this instance runs.">
                <ReadOnlyValue mono={false} value={`${instance.packageDisplayName}${pkg ? ` ${pkg.version}` : ''}`} />
              </SettingRow>
              <SettingRow
                anchor="app-pinned"
                label="Pinned"
                description="Pinned applications stay at the top of this browser’s sidebar. This is a local presentation preference."
              >
                <ToggleControl
                  checked={instance.pinned}
                  onChange={(v) => {
                    void getClient()
                      .applications.setPinned(instanceId, v)
                      .then(() => refresh())
                  }}
                />
              </SettingRow>
            </SettingSubsection>
          </div>
        )
      case 'capabilities':
        return (
          <div className="flex flex-col gap-5" data-testid="app-settings-capabilities">
            <SettingSubsection
              title="Capabilities"
              description="Reported by the application package. Unavailable capabilities explain why — no active-looking controls for things that cannot run here."
            >
              <ul className="flex flex-col">
                {instance.capabilities.map((cap) => {
                  const presentation = capabilityPresentation(cap.status)
                  return (
                    <li key={cap.id} className="flex min-h-11 flex-wrap items-center justify-between gap-x-6 gap-y-1 border-b border-border/60 py-2 last:border-b-0">
                      <div className="min-w-0 flex-1 basis-52">
                        <span className="flex items-center gap-1.5 text-sm font-medium text-foreground">
                          {CAPABILITY_LABELS[cap.id]}
                          <CapabilityDot status={cap.status} reason={cap.reason} />
                        </span>
                        {presentation ? (
                          <span className="mt-0.5 block text-xs text-foreground-secondary">
                            <span>{presentation.label}</span>
                            {cap.reason ? <span>{` — ${cap.reason}`}</span> : null}
                          </span>
                        ) : (
                          <span className="mt-0.5 block text-xs text-foreground-secondary">Available</span>
                        )}
                      </div>
                    </li>
                  )
                })}
              </ul>
            </SettingSubsection>
            {pkg ? (
              <SettingSubsection title="Declared permissions" description="What the package declared at install review. Read-only facts.">
                <SettingRow anchor="perm-files" label="File access">
                  <ReadOnlyValue mono={false} value={pkg.permissions.fileAccess} />
                </SettingRow>
                <SettingRow anchor="perm-terminal" label="Terminal access">
                  <ReadOnlyValue mono={false} value={pkg.permissions.terminalAccess} />
                </SettingRow>
                <SettingRow anchor="perm-network" label="Network access">
                  <ReadOnlyValue mono={false} value={`${pkg.permissions.networkAccess} (policy: ${pkg.networkPolicy.replace('_', ' ')})`} />
                </SettingRow>
                <SettingRow anchor="perm-data" label="Data ownership">
                  <ReadOnlyValue mono={false} value={pkg.permissions.dataOwnership} />
                </SettingRow>
              </SettingSubsection>
            ) : null}
          </div>
        )
      case 'conversation':
        return (
          <div className="flex flex-col gap-5" data-testid="app-settings-conversation">
            <SettingSubsection title="Context" description="Browser presentation preference for this application only.">
              <SettingRow
                anchor="app-context"
                label="Default context selection"
                description="What this browser pre-selects in the composer. The backend compiles and authorizes effective context independently."
              >
                <CheckboxChips
                  ariaLabel="Default context for this application"
                  values={draft.conversation.defaultContext}
                  options={chipOptions}
                  onToggle={(kind, next) =>
                    set([
                      'conversation.defaultContext',
                      next
                        ? [...draft.conversation.defaultContext, kind]
                        : draft.conversation.defaultContext.filter((k) => k !== kind),
                    ])
                  }
                />
              </SettingRow>
            </SettingSubsection>
          </div>
        )
      case 'notifications':
        return (
          <div className="flex flex-col gap-5" data-testid="app-settings-notifications">
            <SettingSubsection title="Notifications" description="Stored in this browser; it does not change backend attention state.">
              <SettingRow
                anchor="app-notif-level"
                label="Notification level"
                description="Overrides this browser’s global notification presentation for this application."
              >
                <SelectControl
                  value={draft.notificationLevel}
                  options={(
                    Object.entries(APP_NOTIFICATION_LEVEL_LABELS) as ['inherit' | 'all' | 'important_only' | 'none', string][]
                  ).map(([value, label]) => ({ value, label }))}
                  onChange={(v) => set(['notificationLevel', v])}
                />
              </SettingRow>
            </SettingSubsection>
          </div>
        )
      case 'context':
        return <ContextLifecycleGroup key={instanceId} instanceId={instanceId} />
      case 'backup':
        return (
          <div className="flex flex-col gap-5" data-testid="app-settings-backup">
            {isMock ? (
              <SettingSubsection title="Schedule">
                <SettingRow anchor="backup-enabled" label="Automatic backups" description="Back up this simulated application on a schedule.">
                  <ToggleControl checked={draft.backup.enabled} onChange={(v) => set(['backup.enabled', v])} />
                </SettingRow>
                {draft.backup.enabled ? (
                  <SettingRow anchor="backup-interval" label="Backup interval" description="How often simulated backups run.">
                    <NumberControl
                      value={draft.backup.intervalHours}
                      min={1}
                      max={720}
                      unit="hours"
                      onChange={(v) => set(['backup.intervalHours', v])}
                    />
                  </SettingRow>
                ) : null}
              </SettingSubsection>
            ) : (
              <InlineNotice tone="informational" title="Scheduling is not exposed by the connected service">
                Recovery facts below are live and read-only. This page does not claim that a browser preference creates an automatic backup.
              </InlineNotice>
            )}
            <SettingSubsection title="Current state" description="Reported by the recovery subsystem. Read-only.">
              <SettingRow anchor="backup-state" label="Backup state">
                <span className="flex items-center gap-2">
                  <StatusBadge
                    state={instance.recovery.state === 'due' ? 'attention' : instance.recovery.state === 'failed' ? 'danger' : 'neutral'}
                    label={RECOVERY_STATE_LABELS[instance.recovery.state] ?? instance.recovery.state}
                  />
                </span>
              </SettingRow>
              <SettingRow anchor="backup-last" label="Last backup">
                <ReadOnlyValue
                  mono={false}
                  value={instance.recovery.lastBackupAt ? new Date(instance.recovery.lastBackupAt).toLocaleString() : 'Never'}
                />
              </SettingRow>
              {instance.recovery.nextDueAt ? (
                <SettingRow anchor="backup-next" label="Next due">
                  <ReadOnlyValue mono={false} value={new Date(instance.recovery.nextDueAt).toLocaleString()} />
                </SettingRow>
              ) : null}
              {instance.recovery.detail ? (
                <SettingRow anchor="backup-detail" label="Detail">
                  <ReadOnlyValue mono={false} value={instance.recovery.detail} />
                </SettingRow>
              ) : null}
            </SettingSubsection>
            <RecoveryRestorePanel instanceId={instanceId} onRestored={refresh} />
          </div>
        )
      case 'advanced':
        return (
          <div className="flex flex-col gap-5" data-testid="app-settings-advanced">
            <SettingSubsection title="Identifiers">
              <SettingRow anchor="app-id" label="Instance ID" description="Stable identifier used in receipts and routes.">
                <ReadOnlyValue value={instance.id} copyValue={instance.id} />
              </SettingRow>
              <SettingRow anchor="app-package-id" label="Package" description="Package identity and version.">
                <ReadOnlyValue value={`${instance.packageName}${pkg ? `@${pkg.version}` : ''}`} copyValue={instance.packageName} />
              </SettingRow>
              <SettingRow anchor="app-created" label="Installed" description="When this instance was created.">
                <ReadOnlyValue mono={false} value={new Date(instance.createdAt).toLocaleString()} />
              </SettingRow>
            </SettingSubsection>
            <SettingSubsection title="Terminal">
              <SettingRow
                anchor="app-terminal-target"
                label="Default target"
                description="The target this browser pre-selects for a new terminal session. Connection still requires an explicit action."
              >
                <SelectControl
                  value={draft.terminal.defaultTargetId ?? ''}
                  options={[
                    { value: '', label: 'Ask every time' },
                    ...targets.map((t) => ({ value: t.id, label: t.available ? t.label : `${t.label} (unavailable)` })),
                  ]}
                  onChange={(v) => set(['terminal.defaultTargetId', v])}
                />
              </SettingRow>
            </SettingSubsection>
            <SettingSubsection title="Raw truth">
              <div className="py-1">
                <Disclosure title="View raw instance descriptor">
                  <pre className="mx-2 mb-2 mt-1 max-h-80 overflow-auto rounded-sm border border-border bg-sunken p-2 font-mono text-code text-foreground-secondary">
                    {JSON.stringify(
                      {
                        id: instance.id,
                        name: instance.name,
                        packageId: instance.packageId,
                        health: instance.health,
                        capabilities: instance.capabilities,
                        recovery: instance.recovery,
                        browserPreferences: draft,
                      },
                      null,
                      2,
                    )}
                  </pre>
                </Disclosure>
              </div>
            </SettingSubsection>
            <SettingSubsection title="Reset">
              <SettingRow
                anchor="app-reset"
                label={isMock ? 'Reset application settings' : 'Reset browser preferences'}
                description={
                  isMock
                    ? 'Restore this application’s settings to the package defaults. The instance itself is not touched.'
                    : 'Clear this device’s presentation preferences for the application. Backend and canonical state are not touched.'
                }
              >
                <Button variant="outline" size="sm" onClick={() => setConfirmReset(true)} data-testid="app-settings-reset">
                  {isMock ? 'Reset app settings' : 'Reset local preferences'}
                </Button>
              </SettingRow>
            </SettingSubsection>
          </div>
        )
      default:
        return null
    }
  }

  const confirmNavDialog = (
    <ConfirmDialog
      open={pendingGroup !== null}
      onOpenChange={(open) => {
        if (!open) setPendingGroup(null)
      }}
      title="Discard unsaved changes?"
      description="You have unsaved application settings changes."
      effect="Switching groups discards the changes that were not saved."
      confirmLabel="Discard changes"
      cancelLabel="Keep editing"
      destructive
      onConfirm={() => {
        const target = pendingGroup
        setPendingGroup(null)
        discard()
        goGroup(target === 'list' ? null : target)
      }}
    />
  )

  const resetDialog = (
    <ConfirmDialog
      open={confirmReset}
      onOpenChange={setConfirmReset}
      title={isMock ? 'Reset application settings?' : 'Reset browser preferences?'}
      description={
        isMock
          ? `Settings for “${instance.name}” return to the package defaults.`
          : `Presentation preferences for “${instance.name}” are cleared from this browser.`
      }
      target={instance.name}
      effect={
        isMock
          ? 'Notification level, conversation context, and backup schedule reset.'
          : 'Notification presentation, composer defaults, and terminal target return to local defaults.'
      }
      reversibility="You can change any setting again afterwards."
      confirmLabel="Reset settings"
      onConfirm={async () => {
        const result = await client.appSettings.reset(instanceId)
        setSaved(result)
        setDraft(result)
        refresh()
        pushToast({
          kind: 'success',
          title: isMock ? 'Application settings reset' : 'Browser preferences reset',
        })
      }}
    />
  )

  // ── Mobile: list → page ────────────────────────────────────────────────────
  if (isMobile) {
    return (
      <div className="flex h-full flex-col bg-app" data-testid="settings-stub">
        <div className="min-h-0 flex-1 overflow-y-auto">
          <div className="flex flex-col gap-3 px-4 pb-8 pt-4">
            {!activeGroup ? (
              <>
                <h1 className="truncate text-xl text-foreground">{instance.name} — Settings</h1>
                <ul className="flex flex-col divide-y divide-border/60" data-testid="app-settings-group-list">
                  {APP_GROUPS.map((g) => (
                    <li key={g.id}>
                      <button
                        type="button"
                        onClick={() => goGroup(g.id)}
                        className="flex min-h-11 w-full items-center justify-between gap-2 py-2 text-left outline-none focus-visible:ring-2 focus-visible:ring-focus"
                      >
                        <span className="min-w-0">
                          <span className="block text-sm font-medium text-foreground">{g.label}</span>
                          <span className="block truncate text-xs text-foreground-secondary">{g.description}</span>
                        </span>
                        <ChevronRight className="size-4 shrink-0 text-foreground-tertiary" aria-hidden="true" />
                      </button>
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <>
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" onClick={() => requestGroup(null)} aria-label="Back to all application settings">
                    <ChevronLeft className="size-4" aria-hidden="true" />
                    All settings
                  </Button>
                </div>
                <header>
                  <h1 className="text-xl text-foreground">{activeMeta?.label}</h1>
                  {activeMeta ? <p className="mt-0.5 text-xs text-foreground-secondary">{activeMeta.description}</p> : null}
                </header>
                {!isMock ? (
                  <InlineNotice tone="informational" title="Authority boundary">
                    Editable presentation preferences stay in this browser. Backend-owned capability, recovery, and context facts remain read-only; canonical application state is not changed here.
                  </InlineNotice>
                ) : null}
                {content()}
              </>
            )}
          </div>
        </div>
        {saveBar}
        {confirmNavDialog}
        {resetDialog}
      </div>
    )
  }

  // ── Desktop / tablet ───────────────────────────────────────────────────────
  return (
    <div className="flex h-full bg-app" data-testid="settings-stub">
      <aside className="hidden w-[200px] shrink-0 overflow-y-auto border-r border-border px-3 py-4 xl:block">
        <p className="truncate px-2 pb-2 text-xs text-foreground-tertiary">{instance.name}</p>
        {groupNav(true)}
      </aside>
      <div className="min-w-0 flex-1 overflow-y-auto" data-testid="settings-page">
        <div className="mx-auto flex max-w-[760px] flex-col gap-4 px-6 pb-10 pt-5">
          <header className="flex flex-col gap-3">
            <h1 className="text-xl text-foreground">{activeMeta ? activeMeta.label : `${instance.name} — Settings`}</h1>
            {activeMeta ? <p className="-mt-2 text-xs text-foreground-secondary">{activeMeta.description}</p> : null}
            <span className="xl:hidden">{groupNav(false)}</span>
          </header>
          {!isMock && activeGroup ? (
            <InlineNotice tone="informational" title="Authority boundary">
              Editable presentation preferences stay in this browser. Backend-owned capability, recovery, and context facts remain read-only; canonical application state is not changed here.
            </InlineNotice>
          ) : null}
          {activeGroup ? content() : null}
        </div>
        {saveBar}
      </div>
      {confirmNavDialog}
      {resetDialog}
    </div>
  )
}
