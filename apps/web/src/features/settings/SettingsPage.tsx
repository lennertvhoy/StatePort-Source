/**
 * SettingsPage — the global settings surface (`#/settings`, `#/settings/:group`)
 * and the host for application-scoped settings (`#/app/:instanceId/settings`).
 *
 * Desktop ≥ 1200 px: two-pane (group nav + content). Tablet: chip strip.
 * Mobile: group list → group page. Search filters settings inline and jumps
 * to group + anchor. The save bar appears only while dirty.
 */
import { ChevronLeft, ChevronRight, Search, Settings } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Navigate, useLocation, useNavigate, useParams } from 'react-router-dom'

import { ConfirmDialog, ErrorState, SkeletonRows } from '@/components'
import { Button } from '@/components/ui/button'
import { getClient } from '@/client'
import { useMediaQuery } from '@/shell/platform'
import { useRegisterCommands } from '@/shell/commands'
import { cn } from '@/lib/utils'

import { AdvancedGroup } from './AdvancedGroup'
import { AppSettingsView } from './AppSettingsView'
import { AppearanceGroup, ConversationGroup, EditorGroup, GeneralGroup, NavigationGroup } from './GlobalGroups'
import { AccessibilityGroup, NotificationsGroup, PrivacyGroup, TerminalGroup } from './GlobalGroups2'
import { ShortcutsGroup } from './ShortcutsGroup'
import { SETTINGS_GROUPS, isSettingsGroupId, matchSetting, scenarioToolsAvailable } from './model'
import type { SettingSearchEntry } from './model'
import { ALL_SEARCH_ENTRIES } from './searchEntries'
import { useGlobalSettings } from './useGlobalSettings'

export default function SettingsPage() {
  const { instanceId } = useParams<{ instanceId: string }>()
  if (instanceId) return <AppSettingsView instanceId={instanceId} />
  return <GlobalSettingsView />
}

function GlobalSettingsView() {
  const { group } = useParams<{ group: string }>()
  const navigate = useNavigate()
  const location = useLocation()
  const isMobile = useMediaQuery('(max-width: 767px)')
  const isTwoPane = useMediaQuery('(min-width: 1200px)')
  const controller = useGlobalSettings()
  const { draft, loading, loadError, dirty, saving, saveError } = controller

  const [query, setQuery] = useState('')
  const [pendingGroup, setPendingGroup] = useState<string | null>(null)
  const searchRef = useRef<HTMLInputElement | null>(null)

  const activeGroup = isSettingsGroupId(group) ? group : undefined
  const searching = query.trim().length > 0
  const showScenarioTools = scenarioToolsAvailable(
    getClient().adapter,
    import.meta.env.DEV ? 'development' : 'production',
  )

  // ── Commands (palette): open each group + search settings ─────────────────
  const commands = useMemo(
    () => [
      ...SETTINGS_GROUPS.map((g) => ({
        id: `settings.group.${g.id}`,
        title: `Open settings: ${g.label}`,
        group: 'Settings' as const,
        icon: Settings,
        run: () => void navigate(`/settings/${g.id}`),
      })),
      {
        id: 'settings.search',
        title: 'Search settings',
        group: 'Settings' as const,
        icon: Search,
        run: () => void navigate('/settings', { state: { focusSearch: true } }),
      },
    ],
    [navigate],
  )
  useRegisterCommands(commands)

  // ── Deep-link handling: invalid groups bounce to the group list ───────────
  useEffect(() => {
    if (group && !activeGroup) void navigate('/settings', { replace: true })
  }, [group, activeGroup, navigate])

  // `/` focuses settings search (settings.md keyboard scope); inputs are safe.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return
      const target = e.target as HTMLElement | null
      if (target && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))) return
      e.preventDefault()
      searchRef.current?.focus()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  // ── Search jumps (anchor scroll) + palette “search settings” focus ────────
  useEffect(() => {
    const state = location.state as { anchor?: string; focusSearch?: boolean } | null
    if (!state) return
    if (state.focusSearch) {
      searchRef.current?.focus()
    }
    if (state.anchor) {
      const el = document.getElementById(`setting-${state.anchor}`)
      if (el) {
        el.scrollIntoView({ block: 'center' })
        el.classList.add('bg-accent-soft/40')
        window.setTimeout(() => el.classList.remove('bg-accent-soft/40'), 1200)
      }
    }
    if (state.focusSearch || state.anchor) void navigate(location.pathname, { replace: true, state: {} })
  }, [location, navigate])

  // ── Results ────────────────────────────────────────────────────────────────
  const results = useMemo(() => {
    if (!searching) return null
    return ALL_SEARCH_ENTRIES.filter(
      (entry) =>
        (showScenarioTools ||
          (entry.anchor !== 'scenario-lab' && entry.anchor !== 'reset-mock')) &&
        matchSetting(entry, query),
    )
  }, [query, searching, showScenarioTools])

  const jumpTo = (entry: SettingSearchEntry) => {
    setQuery('')
    void navigate(`/settings/${entry.group}`, { state: { anchor: entry.anchor } })
  }

  /** Group switches confirm while dirty (settings.md dirty model). */
  const requestGroup = (id: string) => {
    if (dirty) setPendingGroup(id)
    else void navigate(id ? `/settings/${id}` : '/settings')
  }

  const groupNav = (vertical: boolean) => (
    <nav aria-label="Settings groups" className={cn(vertical ? 'flex flex-col gap-0.5' : 'flex gap-1 overflow-x-auto pb-1')}>
      {SETTINGS_GROUPS.map((g) => {
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
              g.advanced && !vertical ? 'ml-2 border-l border-border pl-3' : '',
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
      aria-label="Unsaved settings changes"
      data-testid="settings-save-bar"
    >
      <div className="mx-auto flex max-w-[760px] flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium text-foreground">Unsaved changes</p>
          {saveError ? (
            <p className="text-xs text-status-danger" role="alert">
              Couldn’t save — your changes are still here. {saveError}
            </p>
          ) : (
            <p className="text-xs text-foreground-secondary">Save to apply, or discard to revert.</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={controller.discard} disabled={saving} data-testid="settings-discard">
            Discard
          </Button>
          <Button size="sm" onClick={() => void controller.save()} disabled={saving} data-testid="settings-save">
            {saving ? 'Saving…' : saveError ? 'Retry save' : 'Save'}
          </Button>
        </div>
      </div>
    </div>
  ) : null

  const searchBox = (
    <div className="relative max-w-md">
      <Search className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 text-foreground-tertiary" aria-hidden="true" />
      <input
        ref={searchRef}
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape') setQuery('')
        }}
        placeholder="Search settings…"
        aria-label="Search settings"
        spellCheck={false}
        className="h-control w-full rounded-sm border border-input bg-surface pl-8 pr-2 text-sm text-foreground outline-none placeholder:text-foreground-tertiary focus-visible:border-focus"
        data-testid="settings-search"
      />
    </div>
  )

  const searchResults = searching ? (
    <div className="mt-4" data-testid="settings-search-results">
      {results && results.length > 0 ? (
        <ul className="flex flex-col">
          {results.map((entry) => (
            <li key={`${entry.group}:${entry.anchor}`}>
              <button
                type="button"
                onClick={() => jumpTo(entry)}
                className="flex w-full flex-col gap-0.5 border-b border-border/60 px-1 py-2.5 text-left outline-none transition-colors duration-instant hover:bg-hover focus-visible:ring-2 focus-visible:ring-focus"
              >
                <span className="text-xs text-foreground-tertiary">Settings › {entry.groupLabel}</span>
                <span className="text-sm font-medium text-foreground">{entry.label}</span>
                <span className="text-xs text-foreground-secondary">{entry.description}</span>
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <div className="flex flex-col items-start gap-2 py-8">
          <p className="text-sm text-foreground-secondary">No settings match “{query.trim()}”.</p>
          <Button variant="outline" size="sm" onClick={() => setQuery('')}>
            Reset search
          </Button>
        </div>
      )}
    </div>
  ) : null

  const groupContent = () => {
    if (loading) return <SkeletonRows rows={8} />
    if (loadError) {
      return (
        <ErrorState
          title="Settings couldn’t be loaded"
          error={loadError}
          preservedNote="Nothing was changed."
          onRetry={controller.retryLoad}
        />
      )
    }
    if (!draft || !activeGroup) return null
    switch (activeGroup) {
      case 'general':
        return <GeneralGroup settings={draft} set={controller.set} />
      case 'appearance':
        return <AppearanceGroup settings={draft} set={controller.set} />
      case 'navigation':
        return <NavigationGroup settings={draft} set={controller.set} />
      case 'conversation':
        return <ConversationGroup settings={draft} set={controller.set} />
      case 'editor':
        return <EditorGroup settings={draft} set={controller.set} />
      case 'terminal':
        return <TerminalGroup settings={draft} set={controller.set} />
      case 'notifications':
        return <NotificationsGroup settings={draft} set={controller.set} />
      case 'privacy':
        return <PrivacyGroup settings={draft} set={controller.set} />
      case 'accessibility':
        return <AccessibilityGroup settings={draft} set={controller.set} />
      case 'shortcuts':
        return <ShortcutsGroup />
      case 'advanced':
        return <AdvancedGroup settings={draft} set={controller.set} replaceAll={controller.replaceAll} />
    }
  }

  const activeMeta = SETTINGS_GROUPS.find((g) => g.id === activeGroup)

  // ── Mobile: group list → group page ────────────────────────────────────────
  if (isMobile) {
    return (
      <div className="flex h-full flex-col bg-app" data-testid="settings-stub">
        <div className="min-h-0 flex-1 overflow-y-auto">
          <div className="flex flex-col gap-3 px-4 pb-8 pt-4">
            {!activeGroup ? (
              <>
                <h1 className="text-xl text-foreground">Settings</h1>
                {searchBox}
                {searching ? (
                  searchResults
                ) : (
                  <ul className="flex flex-col divide-y divide-border/60" data-testid="settings-group-list">
                    {SETTINGS_GROUPS.map((g) => (
                      <li key={g.id}>
                        <button
                          type="button"
                          onClick={() => void navigate(`/settings/${g.id}`)}
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
                )}
              </>
            ) : (
              <>
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" onClick={() => requestGroup('')} aria-label="Back to all settings">
                    <ChevronLeft className="size-4" aria-hidden="true" />
                    All settings
                  </Button>
                </div>
                {searchBox}
                {searching ? (
                  searchResults
                ) : (
                  <>
                    <header>
                      <h1 className="text-xl text-foreground">{activeMeta?.label}</h1>
                      {activeMeta ? <p className="mt-0.5 text-xs text-foreground-secondary">{activeMeta.description}</p> : null}
                    </header>
                    {groupContent()}
                  </>
                )}
              </>
            )}
          </div>
        </div>
        {saveBar}
        <ConfirmDialog
          open={pendingGroup !== null}
          onOpenChange={(open) => {
            if (!open) setPendingGroup(null)
          }}
          title="Discard unsaved changes?"
          description="You have unsaved settings changes on this page."
          effect="Leaving discards the changes that were not saved."
          confirmLabel="Discard changes"
          cancelLabel="Keep editing"
          destructive
          onConfirm={() => {
            const target = pendingGroup
            setPendingGroup(null)
            controller.discard()
            void navigate(target ? `/settings/${target}` : '/settings')
          }}
        />
      </div>
    )
  }

  // ── Desktop / tablet ───────────────────────────────────────────────────────
  return (
    <div className="flex h-full bg-app" data-testid="settings-stub">
      {isTwoPane ? (
        <aside className="w-[200px] shrink-0 overflow-y-auto border-r border-border px-3 py-4">
          <p className="px-2 pb-2 text-xs text-foreground-tertiary">Settings</p>
          {groupNav(true)}
        </aside>
      ) : null}
      <div className="min-w-0 flex-1 overflow-y-auto" data-testid="settings-page">
        <div className="mx-auto flex max-w-[760px] flex-col gap-4 px-6 pb-10 pt-5">
          <header className="flex flex-col gap-3">
            <h1 className="text-xl text-foreground">{searching || !activeMeta ? 'Settings' : activeMeta.label}</h1>
            {searchBox}
            {!isTwoPane && !searching ? groupNav(false) : null}
          </header>
          {searching ? (
            searchResults
          ) : activeGroup ? (
            <>
              {activeMeta && isTwoPane ? <p className="-mt-2 text-xs text-foreground-secondary">{activeMeta.description}</p> : null}
              {groupContent()}
            </>
          ) : (
            // No group selected (desktop without deep link): land on General.
            <Navigate to="/settings/general" replace />
          )}
        </div>
        {saveBar}
      </div>
      <ConfirmDialog
        open={pendingGroup !== null}
        onOpenChange={(open) => {
          if (!open) setPendingGroup(null)
        }}
        title="Discard unsaved changes?"
        description="You have unsaved settings changes on this page."
        effect="Switching groups discards the changes that were not saved."
        confirmLabel="Discard changes"
        cancelLabel="Keep editing"
        destructive
        onConfirm={() => {
          const target = pendingGroup
          setPendingGroup(null)
          controller.discard()
          void navigate(target ? `/settings/${target}` : '/settings')
        }}
      />
    </div>
  )
}
