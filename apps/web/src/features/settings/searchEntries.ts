/**
 * Settings search index — every searchable setting (label + description) with
 * its group and stable anchor. Kept component-free so group modules stay
 * fast-refresh clean.
 */
import type { SettingSearchEntry } from './model'

export const generalSearchEntries: SettingSearchEntry[] = [
  { group: 'general', groupLabel: 'General', anchor: 'landing-page', label: 'Default landing page', description: 'Where StatePort starts: Applications or your last workspace.' },
  { group: 'general', groupLabel: 'General', anchor: 'reopen-app', label: 'Reopen last application', description: 'Jump straight back into the application you used last.' },
  { group: 'general', groupLabel: 'General', anchor: 'reopen-view', label: 'Reopen last application view', description: 'Restore the exact view you left open in each application.' },
  { group: 'general', groupLabel: 'General', anchor: 'date-time-format', label: 'Date & time format', description: 'Relative, absolute, or both timestamps across the app.' },
  { group: 'general', groupLabel: 'General', anchor: 'density', label: 'Interface density', description: 'Compact or comfortable spacing. Changes preview instantly.', keywords: ['spacing', 'compact', 'comfortable'] },
  { group: 'general', groupLabel: 'General', anchor: 'confirm-destructive', label: 'Confirm before destructive actions', description: 'Ask for confirmation before irreversible operations.' },
  { group: 'general', groupLabel: 'General', anchor: 'app-sorting', label: 'Default application sorting', description: 'How applications are ordered in lists.' },
  { group: 'general', groupLabel: 'General', anchor: 'show-recents', label: 'Show recent applications', description: 'Surface recently opened applications on the dashboard.' },
  { group: 'general', groupLabel: 'General', anchor: 'restore-layouts', label: 'Restore workspace layouts', description: 'Reopen each application with the panel layout you left.' },
  { group: 'general', groupLabel: 'General', anchor: 'focus-mode', label: 'Start in focus mode', description: 'Begin each session with panels collapsed.' },
  { group: 'general', groupLabel: 'General', anchor: 'search-history', label: 'Remember search history', description: 'Keep recent searches locally on this device.' },
]

export const appearanceSearchEntries: SettingSearchEntry[] = [
  { group: 'appearance', groupLabel: 'Appearance', anchor: 'theme', label: 'Theme', description: 'Follow system, light, dark, or high contrast. Applies instantly.', keywords: ['dark', 'light', 'contrast'] },
  { group: 'appearance', groupLabel: 'Appearance', anchor: 'hc-base', label: 'High-contrast base', description: 'Whether high contrast builds on the light or dark palette.' },
  { group: 'appearance', groupLabel: 'Appearance', anchor: 'font-scale', label: 'Font scale', description: 'Scale all interface text. Applies instantly.', keywords: ['font size', 'text size', 'zoom'] },
  { group: 'appearance', groupLabel: 'Appearance', anchor: 'appearance-density', label: 'Interface density', description: 'Compact or comfortable spacing. Mirrors General → Interface density.' },
  { group: 'appearance', groupLabel: 'Appearance', anchor: 'accent', label: 'Accent preference', description: 'The accent color is fixed to StatePort blue in this build.' },
  { group: 'appearance', groupLabel: 'Appearance', anchor: 'reduced-motion', label: 'Reduced motion', description: 'Reduce nonessential animation. Off follows your system setting.', keywords: ['animation'] },
  { group: 'appearance', groupLabel: 'Appearance', anchor: 'strong-focus', label: 'Stronger focus indicators', description: 'Thicker focus rings for keyboard navigation.' },
  { group: 'appearance', groupLabel: 'Appearance', anchor: 'panel-contrast', label: 'Panel contrast', description: 'Increase border strength between panels.' },
  { group: 'appearance', groupLabel: 'Appearance', anchor: 'code-font', label: 'Code font', description: 'Monospace font used by the editor and terminal.' },
  { group: 'appearance', groupLabel: 'Appearance', anchor: 'editor-theme', label: 'Editor theme', description: 'Editor colors follow the interface or stay light/dark.' },
  { group: 'appearance', groupLabel: 'Appearance', anchor: 'terminal-theme', label: 'Terminal theme', description: 'Terminal colors follow the interface or stay light/dark.' },
]

export const navigationSearchEntries: SettingSearchEntry[] = [
  { group: 'navigation', groupLabel: 'Navigation', anchor: 'sidebar-default', label: 'Sidebar default', description: 'Start with the sidebar expanded or collapsed to a rail.' },
  { group: 'navigation', groupLabel: 'Navigation', anchor: 'auto-collapse', label: 'Auto-collapse below width', description: 'Sidebar collapses automatically below this window width.', keywords: ['sidebar', 'width'] },
  { group: 'navigation', groupLabel: 'Navigation', anchor: 'recent-commands', label: 'Recent commands', description: 'Show recently used commands when the palette opens.' },
  { group: 'navigation', groupLabel: 'Navigation', anchor: 'tool-order', label: 'Workbench tool order', description: 'Order of tools in the workbench header.' },
  { group: 'navigation', groupLabel: 'Navigation', anchor: 'restore-tool', label: 'Restore last tool', description: 'Reopen each application on the workbench tool you used last.' },
  { group: 'navigation', groupLabel: 'Navigation', anchor: 'open-links', label: 'Open links', description: 'Open external links in the current view or a new tab.' },
]

export const conversationSearchEntries: SettingSearchEntry[] = [
  { group: 'conversation', groupLabel: 'Conversation', anchor: 'send-behavior', label: 'Send behavior', description: 'Enter sends the message, or Ctrl+Enter sends and Enter adds a line.', keywords: ['enter', 'send'] },
  { group: 'conversation', groupLabel: 'Conversation', anchor: 'drafts', label: 'Draft persistence', description: 'Keep unsent message drafts in browser storage; previously saved drafts remain until cleared.' },
  { group: 'conversation', groupLabel: 'Conversation', anchor: 'timestamps', label: 'Show message timestamps', description: 'Show when each message was sent.' },
  { group: 'conversation', groupLabel: 'Conversation', anchor: 'compact-messages', label: 'Compact message layout', description: 'Tighter spacing between messages.' },
  { group: 'conversation', groupLabel: 'Conversation', anchor: 'auto-scroll', label: 'Auto-scroll behavior', description: 'Follow new messages or stay where you scrolled.' },
  { group: 'conversation', groupLabel: 'Conversation', anchor: 'confirm-clear', label: 'Confirm before clearing history', description: 'Ask before a conversation is cleared.' },
  { group: 'conversation', groupLabel: 'Conversation', anchor: 'default-context', label: 'Default context inclusion', description: 'What is pre-checked in the composer context picker.', keywords: ['context', 'model', 'privacy'] },
  { group: 'conversation', groupLabel: 'Conversation', anchor: 'delivery-details', label: 'Show delivery details', description: 'Show how each message was delivered and acknowledged.' },
  { group: 'conversation', groupLabel: 'Conversation', anchor: 'tool-events', label: 'Tool events', description: 'Show tool calls collapsed or expanded by default.' },
  { group: 'conversation', groupLabel: 'Conversation', anchor: 'sound-finish', label: 'Sound on response finish', description: 'Play a short sound when the assistant finishes.' },
]

export const editorSearchEntries: SettingSearchEntry[] = [
  { group: 'editor', groupLabel: 'Editor', anchor: 'editor-font', label: 'Font family', description: 'Typeface used in the code editor.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'editor-font-size', label: 'Font size', description: 'Editor font size, 11–20 px.', keywords: ['editor'] },
  { group: 'editor', groupLabel: 'Editor', anchor: 'editor-line-height', label: 'Line height', description: 'Editor line height multiplier.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'tab-size', label: 'Tab size', description: 'How many columns a tab renders as.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'indentation', label: 'Indentation', description: 'Indent with spaces or tabs.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'word-wrap', label: 'Word wrap', description: 'Wrap long lines instead of scrolling horizontally.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'minimap', label: 'Minimap', description: 'Show a condensed overview of the file.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'editor-ligatures', label: 'Ligatures', description: 'Combine characters like => into single glyphs.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'format-on-save', label: 'Format on save', description: 'Formatting runs inside the save preview — it never bypasses review.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'auto-close-brackets', label: 'Auto-close brackets', description: 'Insert the closing bracket automatically.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'show-whitespace', label: 'Show whitespace', description: 'Render spaces and tabs visibly.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'preview-diff', label: 'Preview diff before save', description: 'Review the exact diff before any write is applied.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'restore-files', label: 'Restore open files', description: 'Reopen the files you had open in each application.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'restore-cursor', label: 'Restore cursor positions', description: 'Return the cursor to where you left it in each file.' },
  { group: 'editor', groupLabel: 'Editor', anchor: 'autosave', label: 'Autosave', description: 'Marks files dirty and queues the save preview — never writes directly.', keywords: ['save'] },
]

export const terminalSearchEntries: SettingSearchEntry[] = [
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'terminal-font', label: 'Font', description: 'Typeface used in the terminal.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'terminal-font-size', label: 'Font size', description: 'Terminal font size, 11–20 px.', keywords: ['terminal'] },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'terminal-line-height', label: 'Line height', description: 'Terminal line height multiplier.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'cursor', label: 'Cursor', description: 'Cursor shape and blinking.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'terminal-ligatures', label: 'Ligatures', description: 'Combine character pairs into single glyphs.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'scrollback', label: 'Scrollback lines', description: 'How much output each session keeps.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'copy-on-select', label: 'Copy on select', description: 'Copy selected text to the clipboard immediately.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'right-click', label: 'Right-click behavior', description: 'Paste, show a menu, or select a word.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'multiline-paste', label: 'Multiline paste confirmation', description: 'Warn before pasting multiple lines into a session.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'bell', label: 'Bell', description: 'How the terminal bell presents: off, visual, or sound.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'terminal-sr', label: 'Screen-reader mode', description: 'Render output as an accessible, announcement-friendly log.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'link-handling', label: 'Link handling', description: 'What happens when you click a link in output.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'restore-tabs', label: 'Restore session tabs', description: 'Reopen terminal tabs when you return to an application.' },
  { group: 'terminal', groupLabel: 'Terminal', anchor: 'session-naming', label: 'Session naming', description: 'Name sessions automatically or after their target.' },
]

export const notificationsSearchEntries: SettingSearchEntry[] = [
  { group: 'notifications', groupLabel: 'Notifications', anchor: 'notif-level', label: 'Notification mode', description: 'All notifications, important only, or none.' },
  { group: 'notifications', groupLabel: 'Notifications', anchor: 'approval-alerts', label: 'Approval alerts', description: 'Notify when an approval needs your decision.' },
  { group: 'notifications', groupLabel: 'Notifications', anchor: 'operation-alerts', label: 'Operation-complete alerts', description: 'Notify when a running operation finishes.' },
  { group: 'notifications', groupLabel: 'Notifications', anchor: 'failure-alerts', label: 'Failure alerts', description: 'Notify when an operation fails.' },
  { group: 'notifications', groupLabel: 'Notifications', anchor: 'backup-reminders', label: 'Backup reminders', description: 'Remind when an application backup is due.' },
  { group: 'notifications', groupLabel: 'Notifications', anchor: 'app-overrides', label: 'Application overrides', description: 'Per-application notification levels that override the global mode.' },
  { group: 'notifications', groupLabel: 'Notifications', anchor: 'notif-sound', label: 'Sound', description: 'Play a sound with important notifications.' },
  { group: 'notifications', groupLabel: 'Notifications', anchor: 'quiet-hours', label: 'Quiet hours', description: 'Hold non-critical notifications during a time range.', keywords: ['sleep', 'do not disturb'] },
]

export const privacySearchEntries: SettingSearchEntry[] = [
  { group: 'privacy', groupLabel: 'Privacy & context', anchor: 'selected-files-only', label: 'File context boundary', description: 'Only explicitly selected files may become context.', keywords: ['context', 'selected', 'enforced'] },
  { group: 'privacy', groupLabel: 'Privacy & context', anchor: 'selected-terminal-only', label: 'Terminal context boundary', description: 'Only explicitly selected terminal output may become context.', keywords: ['context', 'selected', 'enforced'] },
  { group: 'privacy', groupLabel: 'Privacy & context', anchor: 'retention', label: 'Conversation retention', description: 'Service conversation history is separate from browser storage.' },
  { group: 'privacy', groupLabel: 'Privacy & context', anchor: 'clear-drafts', label: 'Clear local drafts', description: 'Delete every unsent message draft stored on this device.' },
  { group: 'privacy', groupLabel: 'Privacy & context', anchor: 'clear-search', label: 'Clear search history', description: 'Delete the search history stored on this device.' },
  { group: 'privacy', groupLabel: 'Privacy & context', anchor: 'export-data', label: 'Export settings, drafts & search history', description: 'Download only these three selected local data groups as JSON.' },
  { group: 'privacy', groupLabel: 'Privacy & context', anchor: 'clear-browser-data', label: 'Clear all StatePort browser data', description: 'Delete every StatePort-prefixed localStorage and sessionStorage key without changing backend state.', keywords: ['storage', 'privacy', 'local data', 'session'] },
  { group: 'privacy', groupLabel: 'Privacy & context', anchor: 'telemetry', label: 'Local telemetry', description: 'StatePort does not collect telemetry in this build.' },
  { group: 'privacy', groupLabel: 'Privacy & context', anchor: 'diagnostic-logging', label: 'Diagnostic logging', description: 'Keep verbose local logs for troubleshooting.' },
  { group: 'privacy', groupLabel: 'Privacy & context', anchor: 'attachment-cleanup', label: 'Attachment cleanup', description: 'Service-owned attachments are separate from browser storage.' },
]

export const accessibilitySearchEntries: SettingSearchEntry[] = [
  { group: 'accessibility', groupLabel: 'Accessibility', anchor: 'a11y-font-scale', label: 'Font scale', description: 'Scale all interface text. Mirrors Appearance.', keywords: ['font size', 'text size'] },
  { group: 'accessibility', groupLabel: 'Accessibility', anchor: 'a11y-high-contrast', label: 'High contrast', description: 'Force high-contrast colors regardless of theme.' },
  { group: 'accessibility', groupLabel: 'Accessibility', anchor: 'a11y-reduced-motion', label: 'Reduced motion', description: 'Reduce nonessential animation. Mirrors Appearance.', keywords: ['animation'] },
  { group: 'accessibility', groupLabel: 'Accessibility', anchor: 'a11y-strong-focus', label: 'Strong focus indicators', description: 'Thicker focus rings for keyboard navigation.' },
  { group: 'accessibility', groupLabel: 'Accessibility', anchor: 'a11y-larger-controls', label: 'Larger controls', description: 'Forces comfortable density and larger touch targets.' },
  { group: 'accessibility', groupLabel: 'Accessibility', anchor: 'a11y-sr', label: 'Screen-reader enhancements', description: 'Extra landmarks, labels, and announcements.' },
  { group: 'accessibility', groupLabel: 'Accessibility', anchor: 'a11y-announce', label: 'Announce operation progress', description: 'Speak progress and completion of operations.' },
  { group: 'accessibility', groupLabel: 'Accessibility', anchor: 'a11y-terminal-sr', label: 'Terminal screen-reader mode', description: 'Render terminal output as an accessible log.' },
  { group: 'accessibility', groupLabel: 'Accessibility', anchor: 'a11y-no-animation', label: 'Disable nonessential animation', description: 'Turn off decorative shimmer, slide, and fade effects.' },
]

export const shortcutsSearchEntries: SettingSearchEntry[] = [
  {
    group: 'shortcuts',
    groupLabel: 'Shortcuts',
    anchor: 'shortcut-list',
    label: 'Keyboard shortcuts',
    description: 'Search shortcuts, rebind keys, resolve conflicts, and reset bindings.',
    keywords: ['rebind', 'keys', 'hotkey', 'keyboard'],
  },
]

export const advancedSearchEntries: SettingSearchEntry[] = [
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'adapter-mode', label: 'Adapter mode', description: 'Which backend adapter is active: mock or HTTP.' },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'endpoint', label: 'Service connection', description: 'The startup-selected same-origin service boundary or built-in simulation.' },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'build-info', label: 'Build information', description: 'Version, commit, build time, adapter, and mode.', keywords: ['version'] },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'scenario-lab', label: 'Scenario Lab', description: 'Simulate failures and states (development builds only).' },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'diagnostics', label: 'Diagnostics', description: 'Copy a diagnostic snapshot for support.' },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'export-settings', label: 'Export settings', description: 'Download all settings as a JSON file.' },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'import-settings', label: 'Import settings', description: 'Restore settings from a JSON export, validated before applying.' },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'backend-settings-history', label: 'Backend settings history', description: 'Review and roll back durable backend-owned global settings mutations.', keywords: ['rollback', 'receipt', 'revision'] },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'reset-layout', label: 'Reset layout', description: 'Return every application’s workbench layout to the default.' },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'reset-mock', label: 'Reset mock data', description: 'Wipe and reseed the built-in demo data.' },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'clear-caches', label: 'Clear caches', description: 'Clear cached UI state such as recent commands.' },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'policy', label: 'Inspect effective policy', description: 'The governance rules currently in effect, as data.' },
  { group: 'advanced', groupLabel: 'Advanced', anchor: 'capability-descriptor', label: 'View raw capability descriptor', description: 'Raw capability state of every installed application.' },
]

export const ALL_SEARCH_ENTRIES: readonly SettingSearchEntry[] = [
  ...generalSearchEntries,
  ...appearanceSearchEntries,
  ...navigationSearchEntries,
  ...conversationSearchEntries,
  ...editorSearchEntries,
  ...terminalSearchEntries,
  ...notificationsSearchEntries,
  ...privacySearchEntries,
  ...accessibilitySearchEntries,
  ...shortcutsSearchEntries,
  ...advancedSearchEntries,
]
