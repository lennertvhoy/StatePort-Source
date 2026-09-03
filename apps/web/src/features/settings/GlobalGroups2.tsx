/**
 * Global settings groups — Terminal, Notifications, Privacy & context,
 * Accessibility.
 */
import { useEffect, useState } from 'react'

import type { ApplicationInstance } from '@/client'
import { getClient } from '@/client'
import { ConfirmDialog, InlineNotice } from '@/components'
import { Button } from '@/components/ui/button'
import { useSessionStore, useWorkspaceStore } from '@/state'

import {
  NumberControl,
  ReadOnlyValue,
  SegmentedControl,
  SelectControl,
  SettingRow,
  SettingSubsection,
  TextControl,
  ToggleControl,
} from './controls'
import type { GroupProps } from './GlobalGroups'
import {
  STATEPORT_BROWSER_STORAGE_CATEGORIES,
  clearStatePortBrowserStorage,
  inspectStatePortBrowserStorage,
} from './browserStorage'
import {
  APP_NOTIFICATION_LEVEL_LABELS,
  BELL_LABELS,
  CURSOR_STYLE_LABELS,
  DENSITY_LABELS,
  FONT_SCALE_OPTIONS,
  LINK_HANDLING_LABELS,
  NOTIFICATION_LEVEL_LABELS,
  RIGHT_CLICK_LABELS,
  SESSION_NAMING_LABELS,
  downloadTextFile,
} from './model'

const options = <T extends string>(labels: Record<T, string>) =>
  (Object.entries(labels) as [T, string][]).map(([value, label]) => ({ value, label }))

// ─────────────────────────────────────────────────────────────────────────────
// Terminal
// ─────────────────────────────────────────────────────────────────────────────

export function TerminalGroup({ settings, set }: GroupProps) {
  const t = settings.terminal
  return (
    <div className="flex flex-col gap-5" data-testid="settings-group-terminal">
      <SettingSubsection title="Font & cursor">
        <SettingRow anchor="terminal-font" label="Font" description="Typeface used in the terminal.">
          <TextControl value={t.fontFamily} onChange={(v) => set(['terminal.fontFamily', v])} />
        </SettingRow>
        <SettingRow anchor="terminal-font-size" label="Font size" description="Terminal font size in pixels.">
          <NumberControl value={t.fontSize} min={11} max={20} unit="px" onChange={(v) => set(['terminal.fontSize', v])} />
        </SettingRow>
        <SettingRow anchor="terminal-line-height" label="Line height" description="Terminal line height multiplier.">
          <NumberControl value={t.lineHeight} min={1.05} max={2} step={0.05} onChange={(v) => set(['terminal.lineHeight', v])} />
        </SettingRow>
        <SettingRow anchor="cursor" label="Cursor shape" description="How the cursor renders at the prompt.">
          <SegmentedControl value={t.cursorStyle} options={options(CURSOR_STYLE_LABELS)} onChange={(v) => set(['terminal.cursorStyle', v])} />
        </SettingRow>
        <SettingRow anchor="cursor-blink" label="Cursor blink" description="Blink the cursor while the session is focused.">
          <ToggleControl checked={t.cursorBlink} onChange={(v) => set(['terminal.cursorBlink', v])} />
        </SettingRow>
        <SettingRow anchor="terminal-ligatures" label="Ligatures" description="Combine character pairs into single glyphs where the font supports it.">
          <ToggleControl checked={t.ligatures} onChange={(v) => set(['terminal.ligatures', v])} />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Output">
        <SettingRow anchor="scrollback" label="Scrollback lines" description="How much output each session keeps before truncating.">
          <NumberControl value={t.scrollbackLines} min={100} max={100000} step={100} unit="lines" onChange={(v) => set(['terminal.scrollbackLines', v])} />
        </SettingRow>
        <SettingRow anchor="bell" label="Bell" description="How the terminal bell presents itself.">
          <SelectControl value={t.bell} options={options(BELL_LABELS)} onChange={(v) => set(['terminal.bell', v])} />
        </SettingRow>
        <SettingRow anchor="terminal-sr" label="Screen-reader mode" description="Render output as an accessible log with polite announcements instead of a raw grid.">
          <ToggleControl
            checked={t.screenReaderMode}
            onChange={(v) => set(['terminal.screenReaderMode', v], ['accessibility.terminalScreenReaderMode', v])}
          />
        </SettingRow>
        <SettingRow anchor="link-handling" label="Link handling" description="What happens when you click a link in terminal output.">
          <SelectControl value={t.linkHandling} options={options(LINK_HANDLING_LABELS)} onChange={(v) => set(['terminal.linkHandling', v])} />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Clipboard & pasting">
        <SettingRow anchor="copy-on-select" label="Copy on select" description="Copy selected text to the clipboard immediately.">
          <ToggleControl checked={t.copyOnSelect} onChange={(v) => set(['terminal.copyOnSelect', v])} />
        </SettingRow>
        <SettingRow anchor="right-click" label="Right-click behavior" description="What right-click does inside a terminal session.">
          <SelectControl
            value={t.rightClickBehavior}
            options={options(RIGHT_CLICK_LABELS)}
            onChange={(v) => set(['terminal.rightClickBehavior', v])}
          />
        </SettingRow>
        <SettingRow anchor="multiline-paste" label="Multiline paste confirmation" description="Warn before pasting multiple lines — pasted commands run as if typed.">
          <ToggleControl
            checked={t.multilinePasteConfirmation}
            onChange={(v) => set(['terminal.multilinePasteConfirmation', v])}
          />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Sessions">
        <SettingRow anchor="restore-tabs" label="Restore session tabs" description="Reopen terminal tabs when you return to an application. Sessions are never reconnected automatically.">
          <ToggleControl checked={t.restoreSessionTabs} onChange={(v) => set(['terminal.restoreSessionTabs', v])} />
        </SettingRow>
        <SettingRow anchor="session-naming" label="Session naming" description="How new terminal sessions are named.">
          <SelectControl value={t.sessionNaming} options={options(SESSION_NAMING_LABELS)} onChange={(v) => set(['terminal.sessionNaming', v])} />
        </SettingRow>
      </SettingSubsection>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Notifications
// ─────────────────────────────────────────────────────────────────────────────

export function NotificationsGroup({ settings, set }: GroupProps) {
  const n = settings.notifications
  const [result, setResult] = useState<{ instances: ApplicationInstance[]; error: unknown } | null>(null)

  useEffect(() => {
    let cancelled = false
    getClient()
      .applications.list()
      .then((list) => {
        if (!cancelled) setResult({ instances: list, error: null })
      })
      .catch((err) => {
        // Honest failure: keep any previously loaded list and surface the
        // error — never render an empty application list on access failure.
        if (!cancelled) setResult((prev) => ({ instances: prev?.instances ?? [], error: err }))
      })
    return () => {
      cancelled = true
    }
  }, [])

  const setOverride = (instanceId: string, level: string) => {
    const next = { ...n.applicationOverrides }
    if (level === 'inherit') delete next[instanceId]
    else next[instanceId] = level as 'all' | 'important_only' | 'none'
    set(['notifications.applicationOverrides', next])
  }

  return (
    <div className="flex flex-col gap-5" data-testid="settings-group-notifications">
      <SettingSubsection title="Mode">
        <SettingRow anchor="notif-level" label="Notification mode" description="Important-only still tells you about approvals and failures.">
          <SegmentedControl value={n.level} options={options(NOTIFICATION_LEVEL_LABELS)} onChange={(v) => set(['notifications.level', v])} />
        </SettingRow>
        <SettingRow anchor="notif-sound" label="Sound" description="Play a sound with important notifications.">
          <ToggleControl checked={n.sound} onChange={(v) => set(['notifications.sound', v])} />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Events" description="Choose which events produce a notification.">
        <SettingRow anchor="approval-alerts" label="Approval alerts" description="Notify when an approval needs your decision.">
          <ToggleControl checked={n.approvalAlerts} onChange={(v) => set(['notifications.approvalAlerts', v])} />
        </SettingRow>
        <SettingRow anchor="operation-alerts" label="Operation-complete alerts" description="Notify when a running operation finishes.">
          <ToggleControl checked={n.operationCompleteAlerts} onChange={(v) => set(['notifications.operationCompleteAlerts', v])} />
        </SettingRow>
        <SettingRow anchor="failure-alerts" label="Failure alerts" description="Notify when an operation fails.">
          <ToggleControl checked={n.failureAlerts} onChange={(v) => set(['notifications.failureAlerts', v])} />
        </SettingRow>
        <SettingRow anchor="backup-reminders" label="Backup reminders" description="Remind when an application backup is due.">
          <ToggleControl checked={n.backupReminders} onChange={(v) => set(['notifications.backupReminders', v])} />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Quiet hours" description="Non-critical notifications are held until quiet hours end.">
        <SettingRow anchor="quiet-hours" label="Enable quiet hours" description="Hold non-critical notifications during the range below.">
          <ToggleControl checked={n.quietHours.enabled} onChange={(v) => set(['notifications.quietHours.enabled', v])} />
        </SettingRow>
        {n.quietHours.enabled ? (
          <SettingRow anchor="quiet-hours-range" label="Quiet hours range" description="From / to, local time.">
            <span className="flex items-center gap-2">
              <TextControl type="time" aria-label="Quiet hours from" value={n.quietHours.from} onChange={(v) => set(['notifications.quietHours.from', v])} className="w-28" />
              <span className="text-xs text-foreground-secondary">to</span>
              <TextControl type="time" aria-label="Quiet hours to" value={n.quietHours.to} onChange={(v) => set(['notifications.quietHours.to', v])} className="w-28" />
            </span>
          </SettingRow>
        ) : null}
      </SettingSubsection>

      <SettingSubsection title="Application overrides" description="Per-application levels that override the global mode.">
        {result === null ? (
          <p className="py-2 text-xs text-foreground-secondary">Loading applications…</p>
        ) : result.error ? (
          <p className="py-2 text-xs text-foreground-secondary" data-testid="app-overrides-unavailable">
            Applications could not be loaded — per-application overrides are unavailable right now.
          </p>
        ) : result.instances.length === 0 ? (
          <p className="py-2 text-xs text-foreground-secondary">No applications installed — nothing to override yet.</p>
        ) : (
          result.instances.map((instance) => (
            <SettingRow
              key={instance.id}
              anchor={`override-${instance.id}`}
              label={instance.name}
              description={`${instance.packageDisplayName} — currently ${
                n.applicationOverrides[instance.id]
                  ? APP_NOTIFICATION_LEVEL_LABELS[n.applicationOverrides[instance.id]].toLowerCase()
                  : 'following the global setting'
              }.`}
            >
              <SelectControl
                value={n.applicationOverrides[instance.id] ?? 'inherit'}
                options={options(APP_NOTIFICATION_LEVEL_LABELS)}
                onChange={(v) => setOverride(instance.id, v)}
              />
            </SettingRow>
          ))
        )}
      </SettingSubsection>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Privacy & context
// ─────────────────────────────────────────────────────────────────────────────

export function PrivacyGroup({ settings, set }: GroupProps) {
  const p = settings.privacy
  const client = getClient()
  const drafts = useWorkspaceStore((s) => s.drafts)
  const searchHistory = useWorkspaceStore((s) => s.searchHistory)
  const clearDraft = useWorkspaceStore((s) => s.clearDraft)
  const clearSearchHistory = useWorkspaceStore((s) => s.clearSearchHistory)
  const pushToast = useSessionStore((s) => s.pushToast)
  const [confirmDrafts, setConfirmDrafts] = useState(false)
  const [confirmBrowserData, setConfirmBrowserData] = useState(false)
  const [browserStorage, setBrowserStorage] = useState(() =>
    inspectStatePortBrowserStorage(),
  )

  const draftCount = Object.keys(drafts).length
  const mockMode = client.adapter === 'mock'
  const classifiedStorageKeys = new Set(
    STATEPORT_BROWSER_STORAGE_CATEGORIES.map((category) => category.key),
  )
  const unclassifiedStorageKeys = [
    ...browserStorage.local.keys.map((key) => ({ area: 'Persistent', key })),
    ...browserStorage.session.keys.map((key) => ({ area: 'Per-tab', key })),
  ].filter(({ key }) => !classifiedStorageKeys.has(key))

  const exportLocalData = async () => {
    const settingsJson = await client.globalSettings.exportJson()
    downloadTextFile(
      'stateport-selected-local-data.json',
      JSON.stringify(
        {
          exportedAt: new Date().toISOString(),
          settings: JSON.parse(settingsJson) as unknown,
          drafts,
          searchHistory,
        },
        null,
        2,
      ),
    )
    pushToast({
      kind: 'success',
      title: 'Selected local data exported',
      body: 'The file contains settings, conversation drafts, and search history only.',
    })
  }

  return (
    <div className="flex flex-col gap-5" data-testid="settings-group-privacy">
      <SettingSubsection title="Model context" description="What the assistant may include when you ask something.">
        <InlineNotice tone="informational">
          Default context chips are configured under Conversation. Every included item remains visible and removable before
          send; this privacy boundary cannot be weakened here.
        </InlineNotice>
        <SettingRow
          anchor="selected-files-only"
          label="File context boundary"
          description="StatePort never includes an unselected file or a whole tree implicitly."
        >
          <ReadOnlyValue mono={false} value="Selected files only — enforced" />
        </SettingRow>
        <SettingRow
          anchor="selected-terminal-only"
          label="Terminal context boundary"
          description="StatePort never includes a terminal transcript implicitly."
        >
          <ReadOnlyValue mono={false} value="Selected terminal output only — enforced" />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection
        title="Local data"
        description="Browser presentation state and local-service operational state are separate."
      >
        <SettingRow anchor="retention" label="Conversation retention" description="How long conversations are kept.">
          <ReadOnlyValue
            mono={false}
            value={
              mockMode
                ? 'Scenario Lab conversations are part of the development-only mock browser dataset. They are not production or canonical state.'
                : 'Conversation history is owned by the local StatePort service, not browser storage. Clear it from Conversation; canonical application state remains unchanged.'
            }
          />
        </SettingRow>
        {!settings.conversation.draftPersistence ? (
          <InlineNotice tone="attention">
            <span data-testid="draft-persistence-off">
              Draft persistence is off. New composer text stays in memory only.
              {draftCount > 0
                ? ` ${draftCount} previously saved draft${draftCount === 1 ? '' : 's'} ${draftCount === 1 ? 'remains' : 'remain'} until you clear ${draftCount === 1 ? 'it' : 'them'} below.`
                : ' No saved conversation drafts are currently retained.'}
            </span>
          </InlineNotice>
        ) : null}
        <SettingRow anchor="clear-drafts" label="Clear local drafts" description={`${draftCount} draft${draftCount === 1 ? '' : 's'} stored on this device.`}>
          <Button variant="outline" size="sm" onClick={() => setConfirmDrafts(true)} disabled={draftCount === 0}>
            Clear drafts
          </Button>
        </SettingRow>
        <SettingRow anchor="clear-search" label="Clear search history" description={`${searchHistory.length} recent ${searchHistory.length === 1 ? 'search' : 'searches'} stored on this device.`}>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              clearSearchHistory()
              pushToast({ kind: 'success', title: 'Search history cleared' })
            }}
            disabled={searchHistory.length === 0}
          >
            Clear history
          </Button>
        </SettingRow>
        <SettingRow
          anchor="export-data"
          label="Export settings, drafts & search history"
          description="Download only these three selected data groups as JSON. Other browser preferences, mock data, service conversations, attachments, terminal output, and canonical state are not included."
        >
          <Button variant="outline" size="sm" onClick={() => void exportLocalData()}>
            Export selected JSON
          </Button>
        </SettingRow>
        <SettingRow anchor="attachment-cleanup" label="Attachment cleanup" description="How attachments are cleaned up.">
          <ReadOnlyValue
            mono={false}
            value={
              mockMode
                ? 'Scenario Lab attachments belong to the development-only mock dataset.'
                : 'Attachments are owned by the local StatePort service, not browser storage. Their lifecycle follows the owning conversation.'
            }
          />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection
        title="Browser storage inventory"
        description="Names and purposes are shown; stored values are never exposed here."
      >
        <div
          className="flex flex-col gap-3 py-1"
          data-testid="browser-storage-inventory"
        >
          <p className="text-sm text-foreground">
            <span className="font-medium">{browserStorage.totalKeys}</span>{' '}
            StatePort browser key{browserStorage.totalKeys === 1 ? '' : 's'} currently stored
            {' — '}
            {browserStorage.local.keys.length} persistent and{' '}
            {browserStorage.session.keys.length} per-tab.
          </p>
          <ul className="flex flex-col gap-2">
            {STATEPORT_BROWSER_STORAGE_CATEGORIES.map((category) => {
              const area =
                category.area === 'local'
                  ? browserStorage.local
                  : browserStorage.session
              const present = area.keys.includes(category.key)
              return (
                <li
                  key={`${category.area}:${category.key}`}
                  className="rounded-sm border border-border bg-sunken px-2 py-1.5"
                >
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <code className="break-all text-code text-foreground">
                      {category.key}
                    </code>
                    <span className="text-xs text-foreground-secondary">
                      {category.area === 'local' ? 'Persistent' : 'Per-tab'}
                      {' · '}
                      {area.available
                        ? present
                          ? 'stored now'
                          : 'not currently stored'
                        : 'storage unavailable'}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-foreground-secondary">
                    {category.contents}
                  </p>
                </li>
              )
            })}
            {unclassifiedStorageKeys.map(({ area, key }) => (
              <li
                key={`${area}:${key}`}
                className="rounded-sm border border-status-attention-border bg-status-attention-bg px-2 py-1.5"
              >
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <code className="break-all text-code text-foreground">{key}</code>
                  <span className="text-xs text-status-attention">
                    {area} · stored now · unclassified
                  </span>
                </div>
                <p className="mt-1 text-xs text-foreground-secondary">
                  This StatePort-prefixed key is not in the audited registry. Its
                  value is not displayed; Clear browser data still removes it.
                </p>
              </li>
            ))}
          </ul>
          <InlineNotice tone="informational">
            {mockMode
              ? 'Scenario Lab uses no production service credential. '
              : 'Authentication stays in an HttpOnly service cookie, never Web Storage. '}
            Live terminal output, unsaved file contents, credentials, and provider
            tokens are not persisted by this inventory. Clearing browser data does
            not call the backend or change canonical application state, receipts,
            approvals, service conversations, or attachments.
          </InlineNotice>
        </div>
        <SettingRow
          anchor="clear-browser-data"
          label="Clear all StatePort browser data"
          description="Delete every localStorage and sessionStorage entry whose key begins with “stateport.” Unrelated origin storage and backend state are untouched."
        >
          <Button
            variant="destructive"
            size="sm"
            onClick={() => setConfirmBrowserData(true)}
            data-testid="clear-browser-data"
          >
            Clear browser data
          </Button>
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Diagnostics">
        <SettingRow anchor="telemetry" label="Local telemetry" description="Whether usage data leaves this device.">
          <ReadOnlyValue mono={false} value="Off — StatePort does not collect telemetry in this build." />
        </SettingRow>
        <SettingRow anchor="diagnostic-logging" label="Diagnostic logging" description="Keep verbose local logs for troubleshooting. Logs stay on this device.">
          <ToggleControl checked={p.diagnosticLogging} onChange={(v) => set(['privacy.diagnosticLogging', v])} />
        </SettingRow>
      </SettingSubsection>

      <ConfirmDialog
        open={confirmDrafts}
        onOpenChange={setConfirmDrafts}
        title="Clear local drafts?"
        description="Every unsent message draft stored on this device will be deleted."
        target={`${draftCount} draft${draftCount === 1 ? '' : 's'}`}
        effect="Drafts are removed from local storage immediately."
        reversibility="Not reversible — unsent drafts cannot be recovered."
        confirmLabel="Clear drafts"
        destructive
        onConfirm={() => {
          for (const id of Object.keys(drafts)) clearDraft(id)
          pushToast({ kind: 'success', title: 'Drafts cleared' })
        }}
      />
      <ConfirmDialog
        open={confirmBrowserData}
        onOpenChange={setConfirmBrowserData}
        title="Clear all StatePort browser data?"
        description="Every localStorage and sessionStorage entry whose key begins with “stateport.” will be removed. No service request is made."
        target={`${browserStorage.totalKeys} StatePort browser key${browserStorage.totalKeys === 1 ? '' : 's'}`}
        effect="Persistent UI preferences, local drafts, search history, mock data, and per-tab terminal continuity markers are removed, then this page reloads to discard their in-memory projections. Live terminal output is in memory and is not a stored transcript."
        reversibility="Not reversible. Backend-owned application state, conversations, attachments, approvals, receipts, and settings are unchanged."
        confirmLabel="Clear browser data"
        destructive
        requireTypedConfirmation="clear"
        onConfirm={() => {
          const result = clearStatePortBrowserStorage()
          setBrowserStorage(result.remaining)
          const removed =
            result.removedLocalKeys.length + result.removedSessionKeys.length
          if (result.remaining.totalKeys > 0) {
            pushToast({
              kind: 'error',
              title: 'Some browser data could not be cleared',
              body: `${result.remaining.totalKeys} StatePort browser key${result.remaining.totalKeys === 1 ? '' : 's'} remain. Browser policy may be blocking storage access.`,
            })
            return
          }
          pushToast({
            kind: 'success',
            title: 'StatePort browser data cleared',
            body: `${removed} browser key${removed === 1 ? '' : 's'} removed. Reloading clears the corresponding in-memory presentation state; backend and canonical state were not changed.`,
          })
          // Persisted Zustand and adapter overlays also have live in-memory
          // projections. Reload after the successful prefix-scoped deletion
          // so an ordinary subsequent UI update cannot re-persist the values
          // the user just removed.
          window.location.reload()
        }}
      />
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Accessibility
// ─────────────────────────────────────────────────────────────────────────────

export function AccessibilityGroup({ settings, set }: GroupProps) {
  const a = settings.accessibility
  return (
    <div className="flex flex-col gap-5" data-testid="settings-group-accessibility">
      <InlineNotice tone="informational" className="mb-1">
        These settings mirror their Appearance counterparts where they overlap — changing one updates the other, and they
        preview instantly.
      </InlineNotice>

      <SettingSubsection title="Vision">
        <SettingRow anchor="a11y-font-scale" label="Font scale" description="Scale all interface text. Mirrors Appearance → Font scale.">
          <SegmentedControl
            value={String(a.fontScale)}
            options={FONT_SCALE_OPTIONS}
            onChange={(v) => set(['accessibility.fontScale', Number(v)], ['appearance.fontScale', Number(v)])}
          />
        </SettingRow>
        <SettingRow anchor="a11y-high-contrast" label="High contrast" description="Force high-contrast colors on top of any theme.">
          <ToggleControl checked={a.highContrast} onChange={(v) => set(['accessibility.highContrast', v])} />
        </SettingRow>
        <SettingRow anchor="a11y-larger-controls" label="Larger controls" description="Forces comfortable density so controls and touch targets are larger.">
          <ToggleControl
            checked={a.largerControls}
            onChange={(v) =>
              set(
                ['accessibility.largerControls', v],
                ...(v ? ([['appearance.density', 'comfortable'], ['general.density', 'comfortable']] as const) : []),
              )
            }
          />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Motion & focus">
        <SettingRow anchor="a11y-reduced-motion" label="Reduced motion" description="Reduce nonessential animation. Off follows your system setting.">
          <ToggleControl
            checked={a.reducedMotion}
            onChange={(v) => set(['accessibility.reducedMotion', v], ['appearance.reducedMotion', v])}
          />
        </SettingRow>
        <SettingRow anchor="a11y-no-animation" label="Disable nonessential animation" description="Turns off decorative shimmer, slide, and fade effects even when motion is otherwise allowed.">
          <ToggleControl checked={a.disableNonessentialAnimation} onChange={(v) => set(['accessibility.disableNonessentialAnimation', v])} />
        </SettingRow>
        <SettingRow anchor="a11y-strong-focus" label="Strong focus indicators" description="Thicker, higher-contrast focus rings for keyboard navigation.">
          <ToggleControl
            checked={a.strongFocus}
            onChange={(v) => set(['accessibility.strongFocus', v], ['appearance.strongerFocusIndicators', v])}
          />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Screen reader">
        <SettingRow anchor="a11y-sr" label="Screen-reader enhancements" description="Extra landmarks, labels, and announcements across the app.">
          <ToggleControl checked={a.screenReaderEnhancements} onChange={(v) => set(['accessibility.screenReaderEnhancements', v])} />
        </SettingRow>
        <SettingRow anchor="a11y-announce" label="Announce operation progress" description="Speak progress and completion of long-running operations.">
          <ToggleControl checked={a.announceOperationProgress} onChange={(v) => set(['accessibility.announceOperationProgress', v])} />
        </SettingRow>
        <SettingRow anchor="a11y-terminal-sr" label="Terminal screen-reader mode" description="Render terminal output as an accessible log. Mirrors Terminal → Screen-reader mode.">
          <ToggleControl
            checked={a.terminalScreenReaderMode}
            onChange={(v) => set(['accessibility.terminalScreenReaderMode', v], ['terminal.screenReaderMode', v])}
          />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Density">
        <SettingRow anchor="a11y-density" label="Interface density" description="Current density, mirrored from Appearance.">
          <SegmentedControl
            value={settings.appearance.density}
            options={options(DENSITY_LABELS)}
            onChange={(v) => set(['appearance.density', v], ['general.density', v])}
          />
        </SettingRow>
      </SettingSubsection>
    </div>
  )
}
