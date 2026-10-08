/**
 * ReceiptsNavPanel — the left nav panel for the Receipts tool (receipts.md:
 * "Nav panel = saved filters"): built-in presets (All, This week, File
 * changes, Infrastructure, Approvals & grants, Conversation, Failures) plus
 * user-saved filters. Selecting one applies its patch to the current filter
 * in the workspace store; the canvas reads the same value.
 *
 * Registered by ReceiptsTool via useRegisterToolPanel('receipts', …).
 */
import { Check, Plus, X } from 'lucide-react'
import { useState } from 'react'

import type { WorkbenchSlotProps } from '@/shell/workbench/WorkbenchSlots'
import { cn } from '@/lib/utils'
import { useWorkspaceStore } from '@/state'

import { fromStoredFilter, isPresetActive, RECEIPT_FILTER_PRESETS, toStoredFilter } from './receiptsModel'
import type { ReceiptsViewFilter } from './receiptsModel'
import { useReceiptsUiStore } from './receiptsUiStore'
import type { SavedReceiptFilter } from './receiptsUiStore'

const NO_SAVED: SavedReceiptFilter[] = []

export function ReceiptsNavPanel({ instanceId }: WorkbenchSlotProps) {
  const stored = useWorkspaceStore((s) => s.receiptFilters[instanceId])
  const setReceiptFilter = useWorkspaceStore((s) => s.setReceiptFilter)
  const filter = fromStoredFilter(stored, false)

  const saved = useReceiptsUiStore((s) => s.saved[instanceId]) ?? NO_SAVED
  const saveFilter = useReceiptsUiStore((s) => s.saveFilter)
  const removeFilter = useReceiptsUiStore((s) => s.removeFilter)

  const [naming, setNaming] = useState(false)
  const [name, setName] = useState('')

  const apply = (patch: Partial<ReceiptsViewFilter>) => {
    // View/sort/group prefs survive a filter change; presets reset facets.
    setReceiptFilter(instanceId, toStoredFilter({ ...filter, ...patch }))
  }

  const applySaved = (savedFilter: ReceiptsViewFilter) => {
    setReceiptFilter(instanceId, toStoredFilter({ ...savedFilter, view: filter.view, sort: filter.sort }))
  }

  const commitSave = () => {
    if (!name.trim()) return
    saveFilter(instanceId, name, filter)
    setName('')
    setNaming(false)
  }

  return (
    <nav aria-label="Receipt filters" className="flex flex-col py-1" data-testid="receipts-nav-panel">
      <span className="px-3 pb-1 pt-1.5 text-xs font-medium text-foreground-tertiary">Presets</span>
      <ul className="m-0 list-none p-0">
        {RECEIPT_FILTER_PRESETS.map((preset) => {
          const active = isPresetActive(preset, filter)
          return (
            <li key={preset.id}>
              <button
                type="button"
                aria-current={active || undefined}
                onClick={() => apply(preset.id === 'all' ? { ...preset.patch, view: filter.view, sort: filter.sort } : preset.patch)}
                className={cn(
                  'flex min-h-7 w-full items-center gap-2 px-3 text-left text-sm transition-colors duration-instant',
                  active ? 'bg-accent-soft font-medium text-accent-soft-text' : 'text-foreground hover:bg-hover',
                )}
                data-testid={`receipts-preset-${preset.id}`}
              >
                <span className="flex-1 truncate">{preset.label}</span>
                {active ? <Check className="size-3.5" aria-hidden="true" /> : null}
              </button>
            </li>
          )
        })}
      </ul>

      <span className="flex items-center justify-between px-3 pb-1 pt-3 text-xs font-medium text-foreground-tertiary">
        Saved filters
        <button
          type="button"
          aria-label="Save current filters"
          onClick={() => setNaming((v) => !v)}
          className="inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          data-testid="receipts-save-filter"
        >
          <Plus className="size-3.5" aria-hidden="true" />
        </button>
      </span>

      {naming ? (
        <form
          className="flex items-center gap-1 px-3 pb-1"
          onSubmit={(e) => {
            e.preventDefault()
            commitSave()
          }}
        >
          <input
            // eslint-disable-next-line jsx-a11y/no-autofocus -- explicit user action opened this form
            autoFocus
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Filter name"
            aria-label="Filter name"
            className="h-6 min-w-0 flex-1 rounded-sm border border-input bg-transparent px-1.5 text-xs text-foreground outline-none placeholder:text-foreground-tertiary focus-visible:border-ring"
          />
          <button
            type="submit"
            disabled={!name.trim()}
            className="h-6 rounded-sm bg-accent px-2 text-xs font-medium text-foreground-inverse disabled:opacity-50"
          >
            Save
          </button>
        </form>
      ) : null}

      {saved.length === 0 ? (
        <p className="px-3 py-1 text-xs text-foreground-tertiary">
          {naming ? '' : 'No saved filters — save the current view with +.'}
        </p>
      ) : (
        <ul className="m-0 list-none p-0">
          {saved.map((entry) => (
            <li key={entry.id} className="group flex items-center">
              <button
                type="button"
                onClick={() => applySaved(entry.filter)}
                className="flex min-h-7 min-w-0 flex-1 items-center px-3 text-left text-sm text-foreground transition-colors duration-instant hover:bg-hover"
              >
                <span className="truncate">{entry.name}</span>
              </button>
              <button
                type="button"
                aria-label={`Remove saved filter ${entry.name}`}
                onClick={() => removeFilter(instanceId, entry.id)}
                className="mr-2 inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-tertiary opacity-0 transition-opacity duration-instant hover:bg-hover hover:text-foreground group-hover:opacity-100"
              >
                <X className="size-3" aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </nav>
  )
}
