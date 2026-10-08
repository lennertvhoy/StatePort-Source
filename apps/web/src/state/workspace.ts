/**
 * Workspace store — UI/session continuity (zustand + persist).
 *
 * Holds ONLY client-side UI state; server/domain data flows from the client
 * boundary. Persisted under `stateport.workspace.v1` with a `partialize` that
 * deliberately excludes dangerous state:
 * - open approval dialogs are never restored (they must be revalidated),
 * - terminal sessions are never reconnected just because they were open.
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

import type { ReceiptFilter, WorkbenchToolId } from '@/client'

export const WORKSPACE_STORAGE_KEY = 'stateport.workspace.v1'

export type SidebarMode = 'expanded' | 'collapsed'
export type DateTimeFormatSetting = 'relative' | 'absolute' | 'both'
export type ThemeSetting = 'system' | 'light' | 'dark' | 'high_contrast'
export type DensitySetting = 'compact' | 'comfortable'
export type FontScaleSetting = 87.5 | 100 | 112.5 | 125

export type LayoutPreset =
  | 'focus'
  | 'code'
  | 'code_terminal'
  | 'conversation_files'
  | 'conversation_terminal'
  | 'infrastructure'
  | 'review'

export const DEFAULT_WORKBENCH_TOOL_ORDER: readonly WorkbenchToolId[] = [
  'overview', 'files', 'terminal', 'deployments', 'orchestration', 'receipts',
]

/** Preferences reorder known tools; they never remove tools or add authority. */
export function normalizeWorkbenchToolOrder(value: unknown): WorkbenchToolId[] {
  const selected = Array.isArray(value) ? value : []
  return [...new Set([...selected.filter((id): id is WorkbenchToolId =>
    DEFAULT_WORKBENCH_TOOL_ORDER.includes(id)), ...DEFAULT_WORKBENCH_TOOL_ORDER])]
}

export interface AppLayout {
  navSize: number
  rightDockSize: number
  bottomSize: number
  navCollapsed: boolean
  rightDockCollapsed: boolean
  bottomCollapsed: boolean
  preset: LayoutPreset
  maximizedTool: WorkbenchToolId | null
  focusMode: boolean
}

export const DEFAULT_LAYOUT: AppLayout = {
  navSize: 264,
  rightDockSize: 360,
  bottomSize: 240,
  navCollapsed: false,
  rightDockCollapsed: false,
  bottomCollapsed: false,
  preset: 'code_terminal',
  maximizedTool: null,
  focusMode: false,
}

export interface OpenFile {
  path: string
  cursor?: { line: number; column: number }
}

interface WorkspaceState {
  // ── chrome ──────────────────────────────────────────────────────────────
  sidebar: SidebarMode
  /** True once the user explicitly picked a sidebar mode (wins over auto). */
  sidebarUserChosen: boolean
  /** Saved navigation setting: auto-collapse below this window width. */
  sidebarAutoCollapseBelowPx: number
  theme: ThemeSetting
  density: DensitySetting
  fontScale: FontScaleSetting
  panelContrast: 'default' | 'increased'
  dateTimeFormat: DateTimeFormatSetting
  /** Saved navigation projection, refreshed through the client each session. */
  workbenchToolOrder: WorkbenchToolId[]
  workbenchToolOrderGeneration: number
  /** In-memory ordering token: even a same-value save supersedes initial GET. */
  dateTimeFormatGeneration: number
  highContrast: boolean
  highContrastBase: 'light' | 'dark'
  reducedMotion: boolean
  disableNonessentialAnimation: boolean
  /** "Stronger focus indicators" accessibility setting (design.md §6.4). */
  strongFocus: boolean

  // ── continuity ──────────────────────────────────────────────────────────
  lastInstanceId: string | null
  lastView: string | null
  lastWorkbenchTool: WorkbenchToolId | null
  /** Per-application workbench layout. */
  layouts: Record<string, AppLayout>
  restoreWorkspaceLayouts: boolean
  layoutPersistenceGeneration: number
  /** Per-application open editor files (order = tab order). */
  openFiles: Record<string, OpenFile[]>
  activeFile: Record<string, string | null>
  /** `${instanceId}:${path}` → cursor position. */
  cursorPositions: Record<string, { line: number; column: number }>
  /** conversationId → draft text. */
  drafts: Record<string, string>
  /** instanceId → last receipt filter. */
  receiptFilters: Record<string, ReceiptFilter>
  searchHistory: string[]

  // ── ephemeral UI prefs ──────────────────────────────────────────────────
  notificationQuietMode: boolean
  notificationImportantOnly: boolean

  // ── dangerous / ephemeral (NOT persisted) ───────────────────────────────
  approvalDialogId: string | null
  activeTerminalSession: Record<string, string | null>

  // ── actions ─────────────────────────────────────────────────────────────
  setSidebar(mode: SidebarMode, opts?: { userChosen?: boolean }): void
  toggleSidebar(): void
  setSidebarAutoCollapseBelowPx(px: number): void
  setTheme(theme: ThemeSetting): void
  setDensity(density: DensitySetting): void
  setFontScale(scale: FontScaleSetting): void
  setPanelContrast(contrast: 'default' | 'increased'): void
  setDateTimeFormat(format: DateTimeFormatSetting): void
  setWorkbenchToolOrder(order: unknown): void
  setHighContrast(on: boolean): void
  setHighContrastBase(base: 'light' | 'dark'): void
  setReducedMotion(on: boolean): void
  setDisableNonessentialAnimation(on: boolean): void
  setStrongFocus(on: boolean): void
  setLastOpened(instanceId: string, view?: string | null, tool?: WorkbenchToolId | null): void
  setRestoreWorkspaceLayouts(enabled: boolean, discardRestoredLayouts?: boolean): void
  getLayout(instanceId: string): AppLayout
  setLayout(instanceId: string, patch: Partial<AppLayout>): void
  resetLayout(instanceId: string): void
  setPreset(instanceId: string, preset: LayoutPreset): void
  setMaximizedTool(instanceId: string, tool: WorkbenchToolId | null): void
  setFocusMode(instanceId: string, on: boolean): void
  openFile(instanceId: string, path: string): void
  closeFile(instanceId: string, path: string): void
  setActiveFile(instanceId: string, path: string | null): void
  setCursor(instanceId: string, path: string, cursor: { line: number; column: number }): void
  setDraft(conversationId: string, text: string): void
  clearDraft(conversationId: string): void
  setReceiptFilter(instanceId: string, filter: ReceiptFilter): void
  addSearchHistory(query: string): void
  clearSearchHistory(): void
  setNotificationQuietMode(on: boolean): void
  setNotificationImportantOnly(on: boolean): void
  setApprovalDialog(id: string | null): void
  setActiveTerminalSession(instanceId: string, sessionId: string | null): void
}

const MAX_SEARCH_HISTORY = 20

export const useWorkspaceStore = create<WorkspaceState>()(
  persist(
    (set, get) => ({
      sidebar: 'expanded',
      sidebarUserChosen: false,
      sidebarAutoCollapseBelowPx: 1200,
      theme: 'system',
      density: 'compact',
      fontScale: 100,
      panelContrast: 'default',
      workbenchToolOrder: [...DEFAULT_WORKBENCH_TOOL_ORDER],
      workbenchToolOrderGeneration: 0,
      dateTimeFormat: 'relative',
      dateTimeFormatGeneration: 0,
      highContrast: false,
      highContrastBase: 'dark',
      reducedMotion: false,
      disableNonessentialAnimation: false,
      strongFocus: false,

      lastInstanceId: null,
      lastView: null,
      lastWorkbenchTool: null,
      layouts: {},
      restoreWorkspaceLayouts: true,
      layoutPersistenceGeneration: 0,
      openFiles: {},
      activeFile: {},
      cursorPositions: {},
      drafts: {},
      receiptFilters: {},
      searchHistory: [],

      notificationQuietMode: false,
      notificationImportantOnly: false,

      approvalDialogId: null,
      activeTerminalSession: {},

      setSidebar: (mode, opts) =>
        set({ sidebar: mode, sidebarUserChosen: opts?.userChosen ?? true }),
      setSidebarAutoCollapseBelowPx: (px) =>
        set({ sidebarAutoCollapseBelowPx: Math.min(1920, Math.max(480, Math.round(px))) }),
      toggleSidebar: () =>
        set((s) => ({
          sidebar: s.sidebar === 'expanded' ? 'collapsed' : 'expanded',
          sidebarUserChosen: true,
        })),
      setTheme: (theme) => set({ theme }),
      setDensity: (density) => set({ density }),
      setFontScale: (fontScale) => set({ fontScale }),
      setPanelContrast: (panelContrast) => set({ panelContrast }),
      setDateTimeFormat: (dateTimeFormat) => {
        if (!['relative', 'absolute', 'both'].includes(dateTimeFormat)) throw new Error('Unsupported date/time format')
        set((state) => ({ dateTimeFormat, dateTimeFormatGeneration: state.dateTimeFormatGeneration + 1 }))
      },
      setWorkbenchToolOrder: (order) => set((state) => ({
        workbenchToolOrder: normalizeWorkbenchToolOrder(order),
        workbenchToolOrderGeneration: state.workbenchToolOrderGeneration + 1,
      })),
      setHighContrast: (highContrast) => set({ highContrast }),
      setHighContrastBase: (highContrastBase) => set({ highContrastBase }),
      setReducedMotion: (reducedMotion) => set({ reducedMotion }),
      setDisableNonessentialAnimation: (disableNonessentialAnimation) => set({ disableNonessentialAnimation }),
      setStrongFocus: (strongFocus) => set({ strongFocus }),

      setLastOpened: (instanceId, view, tool) =>
        set((s) => ({
          lastInstanceId: instanceId,
          lastView: view ?? s.lastView,
          lastWorkbenchTool: tool ?? s.lastWorkbenchTool,
        })),

      setRestoreWorkspaceLayouts: (enabled, discardRestoredLayouts = false) =>
        set((s) => ({
          restoreWorkspaceLayouts: enabled,
          layoutPersistenceGeneration: s.layoutPersistenceGeneration + 1,
          // Saving changes future restoration, while current-session editing
          // stays usable. Bootstrap may discard untouched hydrated layouts.
          ...(!enabled && discardRestoredLayouts ? { layouts: {} } : {}),
        })),
      getLayout: (instanceId) => get().layouts[instanceId] ?? DEFAULT_LAYOUT,
      setLayout: (instanceId, patch) =>
        set((s) => ({
          layouts: {
            ...s.layouts,
            [instanceId]: { ...(s.layouts[instanceId] ?? DEFAULT_LAYOUT), ...patch },
          },
        })),
      resetLayout: (instanceId) =>
        set((s) => ({ layouts: { ...s.layouts, [instanceId]: DEFAULT_LAYOUT } })),
      setPreset: (instanceId, preset) =>
        set((s) => {
          const base = s.layouts[instanceId] ?? DEFAULT_LAYOUT
          const collapsed: Partial<AppLayout> =
            preset === 'focus'
              ? { navCollapsed: true, rightDockCollapsed: true, bottomCollapsed: true, focusMode: true }
              : preset === 'code'
                ? { navCollapsed: false, rightDockCollapsed: true, bottomCollapsed: true, focusMode: false }
                : preset === 'infrastructure'
                  ? { navCollapsed: false, rightDockCollapsed: true, bottomCollapsed: false, focusMode: false }
                  : preset === 'review'
                    ? { navCollapsed: true, rightDockCollapsed: false, bottomCollapsed: true, focusMode: false }
                    : { focusMode: false }
          return { layouts: { ...s.layouts, [instanceId]: { ...base, preset, ...collapsed } } }
        }),
      setMaximizedTool: (instanceId, tool) =>
        set((s) => ({
          layouts: {
            ...s.layouts,
            [instanceId]: { ...(s.layouts[instanceId] ?? DEFAULT_LAYOUT), maximizedTool: tool, focusMode: tool !== null },
          },
        })),
      setFocusMode: (instanceId, on) =>
        set((s) => ({
          layouts: {
            ...s.layouts,
            [instanceId]: { ...(s.layouts[instanceId] ?? DEFAULT_LAYOUT), focusMode: on },
          },
        })),

      openFile: (instanceId, path) =>
        set((s) => {
          const files = s.openFiles[instanceId] ?? []
          const next = files.some((f) => f.path === path) ? files : [...files, { path }]
          return {
            openFiles: { ...s.openFiles, [instanceId]: next },
            activeFile: { ...s.activeFile, [instanceId]: path },
          }
        }),
      closeFile: (instanceId, path) =>
        set((s) => {
          const files = (s.openFiles[instanceId] ?? []).filter((f) => f.path !== path)
          const active =
            s.activeFile[instanceId] === path ? (files[files.length - 1]?.path ?? null) : s.activeFile[instanceId]
          return {
            openFiles: { ...s.openFiles, [instanceId]: files },
            activeFile: { ...s.activeFile, [instanceId]: active ?? null },
          }
        }),
      setActiveFile: (instanceId, path) =>
        set((s) => ({ activeFile: { ...s.activeFile, [instanceId]: path } })),
      setCursor: (instanceId, path, cursor) =>
        set((s) => ({
          cursorPositions: { ...s.cursorPositions, [`${instanceId}:${path}`]: cursor },
        })),

      setDraft: (conversationId, text) =>
        set((s) => ({ drafts: { ...s.drafts, [conversationId]: text } })),
      clearDraft: (conversationId) =>
        set((s) => {
          const drafts = { ...s.drafts }
          delete drafts[conversationId]
          return { drafts }
        }),

      setReceiptFilter: (instanceId, filter) =>
        set((s) => ({ receiptFilters: { ...s.receiptFilters, [instanceId]: filter } })),

      addSearchHistory: (query) =>
        set((s) => {
          const q = query.trim()
          if (!q) return s
          const rest = s.searchHistory.filter((h) => h !== q)
          return { searchHistory: [q, ...rest].slice(0, MAX_SEARCH_HISTORY) }
        }),
      clearSearchHistory: () => set({ searchHistory: [] }),

      setNotificationQuietMode: (notificationQuietMode) => set({ notificationQuietMode }),
      setNotificationImportantOnly: (notificationImportantOnly) => set({ notificationImportantOnly }),

      setApprovalDialog: (approvalDialogId) => set({ approvalDialogId }),
      setActiveTerminalSession: (instanceId, sessionId) =>
        set((s) => ({
          activeTerminalSession: { ...s.activeTerminalSession, [instanceId]: sessionId },
        })),
    }),
    {
      name: WORKSPACE_STORAGE_KEY,
      version: 1,
      partialize: (s) => ({
        sidebar: s.sidebar,
        sidebarUserChosen: s.sidebarUserChosen,
        sidebarAutoCollapseBelowPx: s.sidebarAutoCollapseBelowPx,
        theme: s.theme,
        density: s.density,
        fontScale: s.fontScale,
        panelContrast: s.panelContrast,
        dateTimeFormat: s.dateTimeFormat,
        highContrast: s.highContrast,
        highContrastBase: s.highContrastBase,
        reducedMotion: s.reducedMotion,
        disableNonessentialAnimation: s.disableNonessentialAnimation,
        strongFocus: s.strongFocus,
        lastInstanceId: s.lastInstanceId,
        lastView: s.lastView,
        lastWorkbenchTool: s.lastWorkbenchTool,
        restoreWorkspaceLayouts: s.restoreWorkspaceLayouts,
        layouts: s.restoreWorkspaceLayouts ? s.layouts : {},
        openFiles: s.openFiles,
        activeFile: s.activeFile,
        cursorPositions: s.cursorPositions,
        drafts: s.drafts,
        receiptFilters: s.receiptFilters,
        searchHistory: s.searchHistory,
        notificationQuietMode: s.notificationQuietMode,
        notificationImportantOnly: s.notificationImportantOnly,
        // Excluded on purpose: approvalDialogId (must revalidate identity),
        // activeTerminalSession (never auto-reconnect after refresh).
      }),
    },
  ),
)
