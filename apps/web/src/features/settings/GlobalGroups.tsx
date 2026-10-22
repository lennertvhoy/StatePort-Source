/**
 * Global settings groups — General, Appearance, Navigation, Conversation.
 * Every control edits the draft; the dirty bar owns persistence.
 * Each group also exports its settings-search entries (label + description).
 */
import type { GlobalSettings } from '@/client'

import {
  CheckboxChips,
  NumberControl,
  ReadOnlyValue,
  SegmentedControl,
  SelectControl,
  SettingRow,
  SettingSubsection,
  TextControl,
  ToggleControl,
} from './controls'
import type { GlobalSettingsController } from './useGlobalSettings'
import {
  APP_SORT_LABELS,
  AUTO_SCROLL_LABELS,
  CONTEXT_CHIP_LABELS,
  DATE_TIME_FORMAT_LABELS,
  DENSITY_LABELS,
  FONT_SCALE_OPTIONS,
  LANDING_PAGE_LABELS,
  OPEN_LINKS_LABELS,
  PANEL_CONTRAST_LABELS,
  SIDEBAR_DEFAULT_LABELS,
  THEME_LABELS,
} from './model'

export interface GroupProps {
  settings: GlobalSettings
  set: GlobalSettingsController['set']
}

const options = <T extends string>(labels: Record<T, string>) =>
  (Object.entries(labels) as [T, string][]).map(([value, label]) => ({ value, label }))

// ─────────────────────────────────────────────────────────────────────────────
// General
// ─────────────────────────────────────────────────────────────────────────────

export function GeneralGroup({ settings, set }: GroupProps) {
  const g = settings.general
  const absoluteExample = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(2026, 2, 12, 14, 5),
  )
  return (
    <div className="flex flex-col gap-5" data-testid="settings-group-general">
      <SettingSubsection title="Startup" description="What StatePort does when it opens.">
        <SettingRow anchor="landing-page" label="Default landing page" description="Where StatePort starts after launch.">
          <SelectControl
            value={g.defaultLandingPage}
            options={options(LANDING_PAGE_LABELS)}
            onChange={(v) => set(['general.defaultLandingPage', v])}
          />
        </SettingRow>
        <SettingRow anchor="reopen-app" label="Reopen last application" description="Jump straight back into the application you used last.">
          <ToggleControl checked={g.reopenLastApplication} onChange={(v) => set(['general.reopenLastApplication', v])} />
        </SettingRow>
        <SettingRow anchor="reopen-view" label="Reopen last application view" description="Restore the exact view you left open in each application.">
          <ToggleControl checked={g.reopenLastApplicationView} onChange={(v) => set(['general.reopenLastApplicationView', v])} />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Format & density">
        <SettingRow
          anchor="date-time-format"
          label="Date & time format"
          description={`How timestamps appear. Absolute example: ${absoluteExample}.`}
        >
          <SelectControl
            value={g.dateTimeFormat}
            options={options(DATE_TIME_FORMAT_LABELS)}
            onChange={(v) => set(['general.dateTimeFormat', v])}
          />
        </SettingRow>
        <SettingRow anchor="density" label="Interface density" description="Compact or comfortable spacing. Mirrors Appearance → Interface density; previews instantly.">
          <SegmentedControl
            value={g.density}
            options={options(DENSITY_LABELS)}
            onChange={(v) => set(['general.density', v], ['appearance.density', v])}
          />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Applications">
        <SettingRow anchor="app-sorting" label="Default application sorting" description="How applications are ordered in lists and the switcher.">
          <SelectControl
            value={g.defaultApplicationSorting}
            options={options(APP_SORT_LABELS)}
            onChange={(v) => set(['general.defaultApplicationSorting', v])}
          />
        </SettingRow>
        <SettingRow anchor="show-recents" label="Show recent applications" description="Surface recently opened applications on the dashboard.">
          <ToggleControl checked={g.showRecentApplications} onChange={(v) => set(['general.showRecentApplications', v])} />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Workspace">
        <SettingRow anchor="search-history" label="Remember search history" description="Keep recent searches locally on this device. Clear them anytime from Privacy & context.">
          <ToggleControl checked={g.rememberSearchHistory} onChange={(v) => set(['general.rememberSearchHistory', v])} />
        </SettingRow>
        <SettingRow anchor="confirm-destructive" label="Confirm before destructive actions" description="Ask for confirmation before irreversible operations such as resets and revocations.">
          <ToggleControl checked={g.confirmBeforeDestructive} onChange={(v) => set(['general.confirmBeforeDestructive', v])} />
        </SettingRow>
      </SettingSubsection>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Appearance
// ─────────────────────────────────────────────────────────────────────────────

export function AppearanceGroup({ settings, set }: GroupProps) {
  const a = settings.appearance
  return (
    <div className="flex flex-col gap-5" data-testid="settings-group-appearance">
      <SettingSubsection title="Theme" description="Previewed instantly; kept when you save.">
        <SettingRow anchor="theme" label="Theme" description="High contrast follows your system's light/dark preference.">
          <SegmentedControl value={a.theme} options={options(THEME_LABELS)} onChange={(v) => set(['appearance.theme', v])} />
        </SettingRow>
        {a.theme === 'high_contrast' ? (
          <SettingRow anchor="hc-base" label="High-contrast base" description="The palette high contrast builds on when your system preference is unavailable.">
            <SegmentedControl
              value={a.highContrastBase}
              options={[
                { value: 'light', label: 'Light base' },
                { value: 'dark', label: 'Dark base' },
              ]}
              onChange={(v) => set(['appearance.highContrastBase', v])}
            />
          </SettingRow>
        ) : null}
        <SettingRow anchor="accent" label="Accent preference" description="The accent identifies interactivity — links, primary actions, focus.">
          <ReadOnlyValue mono={false} value="StatePort blue (fixed in this build)" />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Text & density">
        <SettingRow anchor="font-scale" label="Font scale" description="Scale all interface text. Nothing important ever renders below 12 px.">
          <SegmentedControl
            value={String(a.fontScale)}
            options={FONT_SCALE_OPTIONS}
            onChange={(v) => set(['appearance.fontScale', Number(v)], ['accessibility.fontScale', Number(v)])}
          />
        </SettingRow>
        <SettingRow anchor="appearance-density" label="Interface density" description="Compact or comfortable spacing. Mirrors General → Interface density.">
          <SegmentedControl
            value={a.density}
            options={options(DENSITY_LABELS)}
            onChange={(v) => set(['appearance.density', v], ['general.density', v])}
          />
        </SettingRow>
        <SettingRow anchor="panel-contrast" label="Panel contrast" description="Increased swaps hairline borders for stronger ones between panels.">
          <SegmentedControl
            value={a.panelContrast}
            options={options(PANEL_CONTRAST_LABELS)}
            onChange={(v) => set(['appearance.panelContrast', v])}
          />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Motion & focus">
        <SettingRow anchor="reduced-motion" label="Reduced motion" description="On: reduce nonessential animation everywhere. Off: follow your system setting.">
          <ToggleControl
            checked={a.reducedMotion}
            onChange={(v) => set(['appearance.reducedMotion', v], ['accessibility.reducedMotion', v])}
          />
        </SettingRow>
        <SettingRow anchor="strong-focus" label="Stronger focus indicators" description="Thicker, higher-contrast focus rings for keyboard navigation.">
          <ToggleControl
            checked={a.strongerFocusIndicators}
            onChange={(v) => set(['appearance.strongerFocusIndicators', v], ['accessibility.strongFocus', v])}
          />
        </SettingRow>
      </SettingSubsection>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Navigation
// ─────────────────────────────────────────────────────────────────────────────

export function NavigationGroup({ settings, set }: GroupProps) {
  const n = settings.navigation
  return (
    <div className="flex flex-col gap-5" data-testid="settings-group-navigation">
      <SettingSubsection title="Sidebar">
        <SettingRow anchor="sidebar-default" label="Sidebar default" description="Start with the sidebar expanded or collapsed to a rail.">
          <SegmentedControl
            value={n.sidebarDefault}
            options={options(SIDEBAR_DEFAULT_LABELS)}
            onChange={(v) => set(['navigation.sidebarDefault', v])}
          />
        </SettingRow>
        <SettingRow anchor="auto-collapse" label="Auto-collapse below width" description="The sidebar collapses automatically below this window width.">
          <NumberControl
            value={n.autoCollapseBelowPx}
            min={480}
            max={1920}
            step={8}
            unit="px"
            onChange={(v) => set(['navigation.autoCollapseBelowPx', v])}
          />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Command palette">
        <SettingRow anchor="recent-commands" label="Recent commands" description="Show recently used commands at the top of an empty palette.">
          <ToggleControl checked={n.recentCommands} onChange={(v) => set(['navigation.recentCommands', v])} />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Links">
        <SettingRow anchor="open-links" label="Open links" description="Where documentation and external links open.">
          <SelectControl value={n.openLinksIn} options={options(OPEN_LINKS_LABELS)} onChange={(v) => set(['navigation.openLinksIn', v])} />
        </SettingRow>
      </SettingSubsection>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversation
// ─────────────────────────────────────────────────────────────────────────────

export function ConversationGroup({ settings, set }: GroupProps) {
  const c = settings.conversation
  return (
    <div className="flex flex-col gap-5" data-testid="settings-group-conversation">
      <SettingSubsection title="Composing">
        <SettingRow anchor="send-behavior" label="Send behavior" description="On desktop: whether Enter sends, or Ctrl+Enter sends and Enter adds a new line.">
          <SegmentedControl
            value={c.enterSends ? 'enter' : 'ctrl_enter'}
            options={[
              { value: 'enter', label: 'Enter sends' },
              { value: 'ctrl_enter', label: 'Ctrl+Enter sends' },
            ]}
            onChange={(v) => set(['conversation.enterSends', v === 'enter'])}
          />
        </SettingRow>
        <SettingRow
          anchor="drafts"
          label="Draft persistence"
          description="Keep unsent message drafts in browser storage per conversation. Turning this off stops future persistence but does not delete drafts already saved; review or clear them under Privacy & context."
        >
          <ToggleControl checked={c.draftPersistence} onChange={(v) => set(['conversation.draftPersistence', v])} />
        </SettingRow>
        <SettingRow anchor="default-context" label="Default context inclusion" description="What is pre-checked in the composer. Nothing is sent until you send it — see Privacy & context.">
          <CheckboxChips
            ariaLabel="Default composer context"
            values={c.defaultContext}
            options={options(CONTEXT_CHIP_LABELS)}
            onToggle={(kind, next) =>
              set([
                'conversation.defaultContext',
                next ? [...c.defaultContext, kind] : c.defaultContext.filter((k) => k !== kind),
              ])
            }
          />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Reading">
        <SettingRow anchor="timestamps" label="Show message timestamps" description="Show when each message was sent.">
          <ToggleControl checked={c.showMessageTimestamps} onChange={(v) => set(['conversation.showMessageTimestamps', v])} />
        </SettingRow>
        <SettingRow anchor="compact-messages" label="Compact message layout" description="Tighter spacing between messages.">
          <ToggleControl checked={c.compactMessageLayout} onChange={(v) => set(['conversation.compactMessageLayout', v])} />
        </SettingRow>
        <SettingRow anchor="auto-scroll" label="Auto-scroll behavior" description="Whether the conversation follows new messages.">
          <SelectControl value={c.autoScroll} options={options(AUTO_SCROLL_LABELS)} onChange={(v) => set(['conversation.autoScroll', v])} />
        </SettingRow>
        <SettingRow anchor="tool-events" label="Tool events" description="How tool calls render inside the conversation.">
          <SegmentedControl
            value={c.toolEventsExpanded ? 'expanded' : 'collapsed'}
            options={[
              { value: 'collapsed', label: 'Collapsed' },
              { value: 'expanded', label: 'Expanded' },
            ]}
            onChange={(v) => set(['conversation.toolEventsExpanded', v === 'expanded'])}
          />
        </SettingRow>
        <SettingRow anchor="delivery-details" label="Show delivery details" description="Show how each message was delivered and acknowledged.">
          <ToggleControl checked={c.showDeliveryDetails} onChange={(v) => set(['conversation.showDeliveryDetails', v])} />
        </SettingRow>
      </SettingSubsection>

      <SettingSubsection title="Safety & sound">
        <SettingRow anchor="confirm-clear" label="Confirm before clearing history" description="Ask before a conversation is cleared.">
          <ToggleControl checked={c.confirmBeforeClearingHistory} onChange={(v) => set(['conversation.confirmBeforeClearingHistory', v])} />
        </SettingRow>
        <SettingRow anchor="sound-finish" label="Sound on response finish" description="Play a short sound when the assistant finishes responding.">
          <ToggleControl checked={c.soundOnResponseFinished} onChange={(v) => set(['conversation.soundOnResponseFinished', v])} />
        </SettingRow>
      </SettingSubsection>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// TextControl re-export (used by later groups; keeps imports in one place)
// ─────────────────────────────────────────────────────────────────────────────
export { TextControl }
