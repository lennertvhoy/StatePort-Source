/**
 * Settings model — group metadata, human labels (never raw enums), the
 * settings-search entry contract, and pure helpers shared by the global and
 * application-scoped settings surfaces.
 *
 * Binding rules (design.md settings.md):
 * - Human labels instead of raw enum values everywhere.
 * - Read-only effective values render as wrapping text, never disabled inputs.
 * - Every editable control writes through client.globalSettings /
 *   client.appSettings / the workspace store / the shortcuts store.
 */
import type {
  CapabilityId,
  ContextChipKind,
  GlobalSettings,
  WorkbenchToolId,
} from '@/client'
import { useWorkspaceStore } from '@/state'
import type { DensitySetting, FontScaleSetting, ThemeSetting } from '@/state'

// ─────────────────────────────────────────────────────────────────────────────
// Groups
// ─────────────────────────────────────────────────────────────────────────────

export type SettingsGroupId =
  | 'general'
  | 'appearance'
  | 'navigation'
  | 'conversation'
  | 'editor'
  | 'terminal'
  | 'notifications'
  | 'privacy'
  | 'accessibility'
  | 'shortcuts'
  | 'advanced'

export interface SettingsGroupMeta {
  id: SettingsGroupId
  label: string
  description: string
  /** Advanced is visually separated from daily-use groups (settings.md). */
  advanced?: boolean
}

export const SETTINGS_GROUPS: readonly SettingsGroupMeta[] = [
  { id: 'general', label: 'General', description: 'Startup, landing page, dates, and workspace continuity.' },
  { id: 'appearance', label: 'Appearance', description: 'Theme, font scale, density, and code fonts. Changes preview instantly.' },
  { id: 'navigation', label: 'Navigation', description: 'Sidebar, command palette, and workbench tool behavior.' },
  { id: 'conversation', label: 'Conversation', description: 'Sending, drafts, timestamps, scrolling, and default context.' },
  { id: 'editor', label: 'Editor', description: 'Font, indentation, wrapping, and save-preview behavior.' },
  { id: 'terminal', label: 'Terminal', description: 'Font, cursor, scrollback, paste safety, and sessions.' },
  { id: 'notifications', label: 'Notifications', description: 'What reaches you, per-application overrides, and quiet hours.' },
  { id: 'privacy', label: 'Privacy & context', description: 'What the model can see, local data, and telemetry.' },
  { id: 'accessibility', label: 'Accessibility', description: 'Vision, motion, focus, and screen-reader support.' },
  { id: 'shortcuts', label: 'Shortcuts', description: 'Search, rebind, and reset keyboard shortcuts.' },
  { id: 'advanced', label: 'Advanced', description: 'Adapter, build information, import/export, and resets.', advanced: true },
]

export function isSettingsGroupId(value: string | undefined): value is SettingsGroupId {
  return Boolean(value) && SETTINGS_GROUPS.some((g) => g.id === value)
}

// ─────────────────────────────────────────────────────────────────────────────
// Search
// ─────────────────────────────────────────────────────────────────────────────

export interface SettingSearchEntry {
  /** Group this setting lives in. */
  group: string
  groupLabel: string
  /** Stable anchor used for scroll jumps (`setting-<anchor>`). */
  anchor: string
  label: string
  description: string
  keywords?: string[]
}

/** Case-insensitive match over label + description + keywords. */
export function matchSetting(entry: SettingSearchEntry, query: string): boolean {
  const q = query.trim().toLowerCase()
  if (!q) return false
  const haystack = `${entry.label} ${entry.description} ${(entry.keywords ?? []).join(' ')}`.toLowerCase()
  return q.split(/\s+/).every((token) => haystack.includes(token))
}

/** Mock mutation and Scenario Lab controls never belong in an HTTP build. */
export function scenarioToolsAvailable(
  adapter: 'mock' | 'http',
  mode: 'development' | 'production',
): boolean {
  return adapter === 'mock' && mode === 'development'
}

// ─────────────────────────────────────────────────────────────────────────────
// Human labels (never render raw enum values — settings.md “Do NOT show”)
// ─────────────────────────────────────────────────────────────────────────────

export const LANDING_PAGE_LABELS: Record<GlobalSettings['general']['defaultLandingPage'], string> = {
  applications: 'Applications',
  last_workspace: 'Last workspace',
}

export const DATE_TIME_FORMAT_LABELS: Record<GlobalSettings['general']['dateTimeFormat'], string> = {
  relative: 'Relative (“2 hours ago”)',
  absolute: 'Absolute (“14:05, 12 Mar”)',
  both: 'Both',
}

export const DENSITY_LABELS: Record<DensitySetting, string> = {
  compact: 'Compact',
  comfortable: 'Comfortable',
}

export const APP_SORT_LABELS: Record<GlobalSettings['general']['defaultApplicationSorting'], string> = {
  recent: 'Recently opened',
  name: 'Name (A–Z)',
  manual: 'Manual order',
}

export const THEME_LABELS: Record<ThemeSetting, string> = {
  system: 'Follow system',
  light: 'Light',
  dark: 'Dark',
  high_contrast: 'High contrast',
}

export const FONT_SCALE_LABELS: Record<FontScaleSetting, string> = {
  '87.5': 'Compact (87.5%)',
  '100': 'Default (100%)',
  '112.5': 'Large (112.5%)',
  '125': 'Extra large (125%)',
}

/**
 * Ordered options — integer-like record keys ("100") reorder in JS objects,
 * so never derive this list via Object.entries(FONT_SCALE_LABELS).
 */
export const FONT_SCALE_OPTIONS: readonly { value: string; label: string }[] = [
  { value: '87.5', label: FONT_SCALE_LABELS[87.5] },
  { value: '100', label: FONT_SCALE_LABELS[100] },
  { value: '112.5', label: FONT_SCALE_LABELS[112.5] },
  { value: '125', label: FONT_SCALE_LABELS[125] },
]

export const PANEL_CONTRAST_LABELS: Record<GlobalSettings['appearance']['panelContrast'], string> = {
  default: 'Normal',
  increased: 'Increased',
}

export const CODE_FONT_OPTIONS: { value: string; label: string }[] = [
  { value: 'JetBrains Mono', label: 'JetBrains Mono' },
  { value: 'system', label: 'System monospace' },
]

export const UI_THEME_LABELS: Record<GlobalSettings['appearance']['editorTheme'], string> = {
  match_interface: 'Follow interface',
  light: 'Light',
  dark: 'Dark',
}

export const SIDEBAR_DEFAULT_LABELS: Record<GlobalSettings['navigation']['sidebarDefault'], string> = {
  expanded: 'Expanded',
  collapsed: 'Collapsed',
}

export const OPEN_LINKS_LABELS: Record<GlobalSettings['navigation']['openLinksIn'], string> = {
  current_view: 'Current view',
  new_tab: 'New tab',
}

export const AUTO_SCROLL_LABELS: Record<GlobalSettings['conversation']['autoScroll'], string> = {
  always: 'Follow new messages',
  when_at_bottom: 'Only when already at the bottom',
  never: 'Manual',
}

export const CONTEXT_CHIP_LABELS: Record<ContextChipKind, string> = {
  application: 'Application',
  file: 'Open files',
  selection: 'Current selection',
  terminal: 'Terminal output',
  plan: 'Active plan',
  approval: 'Pending approvals',
  receipt: 'Recent receipts',
  summary: 'Conversation summary',
}

export const INDENT_LABELS: Record<GlobalSettings['editor']['indentWith'], string> = {
  spaces: 'Spaces',
  tabs: 'Tabs',
}

export const CURSOR_STYLE_LABELS: Record<GlobalSettings['terminal']['cursorStyle'], string> = {
  block: 'Block',
  underline: 'Underline',
  bar: 'Bar',
}

export const RIGHT_CLICK_LABELS: Record<GlobalSettings['terminal']['rightClickBehavior'], string> = {
  paste: 'Paste',
  context_menu: 'Show context menu',
  select_word: 'Select word',
}

export const BELL_LABELS: Record<GlobalSettings['terminal']['bell'], string> = {
  off: 'Off',
  visual: 'Visual flash',
  sound: 'Sound',
}

export const LINK_HANDLING_LABELS: Record<GlobalSettings['terminal']['linkHandling'], string> = {
  confirm: 'Ask before opening',
  open: 'Open directly',
  copy: 'Copy link address',
}

export const SESSION_NAMING_LABELS: Record<GlobalSettings['terminal']['sessionNaming'], string> = {
  sequential: 'Automatic (numbered)',
  target_based: 'Based on target',
}

export const NOTIFICATION_LEVEL_LABELS: Record<GlobalSettings['notifications']['level'], string> = {
  all: 'All notifications',
  important_only: 'Important only',
  none: 'None',
}

export const APP_NOTIFICATION_LEVEL_LABELS: Record<'inherit' | 'all' | 'important_only' | 'none', string> = {
  inherit: 'Follow global setting',
  all: 'All notifications',
  important_only: 'Important only',
  none: 'None',
}

export const ADAPTER_LABELS: Record<GlobalSettings['advanced']['adapterMode'], string> = {
  mock: 'Mock (built-in simulation)',
  http: 'HTTP (local StatePort service)',
}

export const WORKBENCH_TOOL_LABELS: Record<WorkbenchToolId, string> = {
  overview: 'Overview',
  files: 'Files',
  terminal: 'Terminal',
  deployments: 'Deployments',
  orchestration: 'Orchestration',
  receipts: 'Receipts',
}

export const CAPABILITY_LABELS: Record<CapabilityId, string> = {
  conversation: 'Conversation',
  workbench: 'Workbench',
  file_viewer: 'File viewer',
  editor: 'Editor',
  terminal: 'Terminal',
  progress_dashboard: 'Progress dashboard',
  goal_execution: 'Goal execution',
  cto_orchestration: 'CTO orchestration',
  benchmark_evidence: 'Benchmark evidence',
  proactive_notifications: 'Proactive notifications',
  backup: 'Backup & recovery',
  infrastructure: 'Infrastructure',
  receipts: 'Receipts',
}

export const RECOVERY_STATE_LABELS: Record<string, string> = {
  current: 'Up to date',
  due: 'Backup due',
  running: 'Backup running',
  failed: 'Last backup failed',
  not_configured: 'Not configured',
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Immutable set at a dot path (`appearance.theme`). Arrays are indexed by number. */
export function setPath<T>(obj: T, path: string, value: unknown): T {
  const keys = path.split('.')
  const clone = (Array.isArray(obj) ? [...obj] : { ...(obj as Record<string, unknown>) }) as Record<string, unknown> & T
  let cursor: Record<string, unknown> = clone as Record<string, unknown>
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i]
    const next = cursor[key]
    const nextClone = (Array.isArray(next) ? [...next] : { ...(next as Record<string, unknown>) }) as Record<string, unknown>
    cursor[key] = nextClone
    cursor = nextClone
  }
  cursor[keys[keys.length - 1]] = value
  return clone
}

/** Immutable multi-set. */
export function setPaths<T>(obj: T, entries: readonly (readonly [string, unknown])[]): T {
  return entries.reduce((acc, [path, value]) => setPath(acc, path, value), obj)
}

/** JSON-safe deep equality (settings are plain JSON). */
export function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b)
}

/** Trigger a browser download of a text file. */
export function downloadTextFile(filename: string, text: string, mime = 'application/json'): void {
  const blob = new Blob([text], { type: mime })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

/**
 * Apply the appearance/accessibility slice of settings to the workspace store
 * so the ThemeEngine reflects them (live preview + after save).
 */
export function applyAppearanceToWorkspace(settings: GlobalSettings): void {
  const workspace = useWorkspaceStore.getState()
  workspace.setTheme(settings.appearance.theme)
  workspace.setDensity(settings.appearance.density)
  workspace.setFontScale(settings.appearance.fontScale)
  workspace.setReducedMotion(settings.appearance.reducedMotion)
  workspace.setStrongFocus(settings.appearance.strongerFocusIndicators)
  workspace.setHighContrast(settings.accessibility.highContrast)
}

/** Apply non-appearance settings to the workspace store after a save. */
export function applySavedSettingsToWorkspace(settings: GlobalSettings): void {
  applyAppearanceToWorkspace(settings)
  const workspace = useWorkspaceStore.getState()
  // The saved default is a default, not a permanent pin: it must not mark the
  // sidebar as explicitly user-chosen, or auto-collapse would never apply.
  workspace.setSidebar(settings.navigation.sidebarDefault, { userChosen: false })
  workspace.setSidebarAutoCollapseBelowPx(settings.navigation.autoCollapseBelowPx)
  workspace.setNotificationImportantOnly(settings.notifications.level === 'important_only')
  workspace.setNotificationQuietMode(settings.notifications.level === 'none')
}
