/**
 * ShortcutsReference (`?`) — grouped, platform-aware shortcut table with
 * search, inline conflict errors, and a "Rebind" jump to Settings →
 * Shortcuts (design.md §9.7, §14 ShortcutsDialog).
 */
import { Keyboard, TriangleAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { Kbd } from '@/components'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { SHORTCUT_COMMANDS, useShortcutsStore } from '@/state'

import { useCommandStore } from './commands'
import { formatChord } from './platform'

const GROUP_ORDER = ['Global', 'Workbench', 'Files', 'Conversation', 'Terminal'] as const

export function ShortcutsReference() {
  const open = useCommandStore((s) => s.shortcutsOpen)
  const setOpen = useCommandStore((s) => s.setShortcutsOpen)
  const list = useShortcutsStore((s) => s.list)
  const [query, setQuery] = useState('')
  const navigate = useNavigate()

  const rows = useMemo(() => {
    const all = list()
    const trimmed = query.trim().toLowerCase()
    const filtered = trimmed
      ? all.filter((cmd) => cmd.label.toLowerCase().includes(trimmed) || cmd.keys.includes(trimmed))
      : all
    return GROUP_ORDER.map((group) => ({ group, rows: filtered.filter((cmd) => cmd.group === group) })).filter(
      (g) => g.rows.length > 0,
    )
  }, [list, query])

  const rebind = () => {
    setOpen(false)
    void navigate('/settings/shortcuts')
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent
        className="flex max-h-[80vh] w-[560px] max-w-[92vw] flex-col gap-0 overflow-hidden rounded-lg border border-border bg-surface p-0 shadow-2"
        data-testid="shortcuts-reference"
      >
        <DialogTitle className="flex items-center gap-2 border-b border-border px-4 py-3 text-xl text-foreground">
          <Keyboard className="size-5 text-foreground-secondary" aria-hidden="true" />
          Keyboard shortcuts
        </DialogTitle>
        <div className="border-b border-border px-4 py-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter shortcuts…"
            aria-label="Filter shortcuts"
            className="h-control w-full rounded-sm border border-input bg-surface px-2 text-sm text-foreground outline-none placeholder:text-foreground-tertiary"
            spellCheck={false}
          />
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-2">
          {rows.length === 0 ? (
            <p className="py-6 text-center text-sm text-foreground-secondary">No shortcuts match.</p>
          ) : (
            rows.map(({ group, rows: groupRows }) => (
              <section key={group} className="py-1" aria-label={`${group} shortcuts`}>
                <h3 className="py-1 text-xs font-medium text-foreground-secondary">{group}</h3>
                <ul className="flex flex-col">
                  {groupRows.map((cmd) => (
                    <li key={cmd.id} className="flex items-center justify-between gap-3 py-1">
                      <span className="min-w-0">
                        <span className="block truncate text-sm text-foreground">{cmd.label}</span>
                        {cmd.conflictWith ? (
                          <span className="flex items-center gap-1 text-xs text-status-danger">
                            <TriangleAlert className="size-3" aria-hidden="true" />
                            Conflicts with “{SHORTCUT_COMMANDS.find((c) => c.id === cmd.conflictWith)?.label ?? cmd.conflictWith}”
                          </span>
                        ) : null}
                      </span>
                      <span className="flex shrink-0 items-center gap-2">
                        {cmd.overridden ? <span className="text-xs text-foreground-tertiary">rebound</span> : null}
                        <Kbd>{formatChord(cmd.keys)}</Kbd>
                      </span>
                    </li>
                  ))}
                </ul>
              </section>
            ))
          )}
        </div>
        <div className="flex items-center justify-between gap-2 border-t border-border px-4 py-2">
          <span className="text-xs text-foreground-tertiary">Rebindable in Settings → Shortcuts</span>
          <Button size="sm" variant="ghost" onClick={rebind}>
            Rebind shortcuts
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
