/**
 * ReceiptsFilterBar — the receipts.md filter bar: SearchInput ("Search
 * receipts…"), labeled facet controls (Result · Action · Actor · Date
 * range), the Table/Timeline SegmentedControl, and the Export menu (JSON /
 * CSV of the filtered set).
 *
 * On mobile the facets collapse into a `Filter` button with an active-count
 * badge opening a bottom-sheet Drawer; the view toggle moves into that
 * sheet (timeline is the mobile default).
 */
import { Check, Download, LayoutList, ListFilter, Search, Table2, X } from 'lucide-react'
import { useState } from 'react'

import type { ReceiptResult } from '@/client'
import { Drawer, Tooltip } from '@/components'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import { cn } from '@/lib/utils'

import { ACTION_KIND_GROUPS, activeFilterCount } from './receiptsModel'
import type { ReceiptDateRange, ReceiptsViewFilter, ReceiptsViewMode } from './receiptsModel'

// ─────────────────────────────────────────────────────────────────────────────
// Options
// ─────────────────────────────────────────────────────────────────────────────

const RESULT_OPTIONS: { value: ReceiptResult | 'all'; label: string }[] = [
  { value: 'all', label: 'All results' },
  { value: 'approved', label: 'Approved' },
  { value: 'applied', label: 'Applied' },
  { value: 'executed', label: 'Executed' },
  { value: 'completed', label: 'Completed' },
  { value: 'validated', label: 'Validated' },
  { value: 'completed_without_change', label: 'No changes' },
  { value: 'failed', label: 'Failed' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'cancelled', label: 'Cancelled' },
  { value: 'human_accepted', label: 'Accepted' },
]

const ACTION_OPTIONS: { value: string; label: string }[] = [
  { value: 'all', label: 'All actions' },
  ...ACTION_KIND_GROUPS.map((g) => ({ value: g.id, label: g.label })),
  { value: 'other', label: 'Other' },
]

const ACTOR_OPTIONS = [
  { value: 'all', label: 'All actors' },
  { value: 'user', label: 'You' },
  { value: 'assistant', label: 'Assistant' },
  { value: 'system', label: 'System' },
] as const

const DATE_OPTIONS: { value: ReceiptDateRange; label: string }[] = [
  { value: 'all', label: 'Any time' },
  { value: 'day', label: 'Last 24 hours' },
  { value: 'week', label: 'Last 7 days' },
  { value: 'month', label: 'Last 30 days' },
]

// ─────────────────────────────────────────────────────────────────────────────
// Search input (SearchInput pattern: Esc clears, keyboard hint)
// ─────────────────────────────────────────────────────────────────────────────

export function ReceiptSearchInput({
  value,
  onChange,
  inputRef,
  className,
}: {
  value: string
  onChange: (value: string) => void
  inputRef?: React.RefObject<HTMLInputElement | null>
  className?: string
}) {
  return (
    <div className={cn('relative flex items-center', className)}>
      <Search className="pointer-events-none absolute left-2 size-3.5 text-foreground-tertiary" aria-hidden="true" />
      <input
        ref={inputRef}
        type="search"
        role="searchbox"
        aria-label="Search receipts"
        placeholder="Search receipts…"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape' && value) {
            e.stopPropagation()
            onChange('')
          }
        }}
        className="h-7 w-full rounded-sm border border-input bg-transparent pl-7 pr-7 text-sm text-foreground outline-none transition-colors duration-instant placeholder:text-foreground-tertiary focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/40"
        data-testid="receipts-search"
      />
      {value ? (
        <button
          type="button"
          aria-label="Clear search"
          onClick={() => onChange('')}
          className="absolute right-1 inline-flex min-h-5 min-w-5 items-center justify-center rounded-sm text-foreground-tertiary transition-colors duration-instant hover:bg-hover hover:text-foreground"
        >
          <X className="size-3.5" aria-hidden="true" />
        </button>
      ) : null}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Facet selects (labeled; compact)
// ─────────────────────────────────────────────────────────────────────────────

function FacetSelect({
  label,
  value,
  options,
  onChange,
  testId,
}: {
  label: string
  value: string
  options: readonly { value: string; label: string }[]
  onChange: (value: string) => void
  testId: string
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger aria-label={label} className="h-7 w-auto min-w-0 gap-1 rounded-sm border-input px-2 text-xs" data-testid={testId}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent className="bg-surface">
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value} className="text-xs">
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// View toggle (SegmentedControl: Table / Timeline)
// ─────────────────────────────────────────────────────────────────────────────

export function ViewToggle({ value, onChange }: { value: ReceiptsViewMode; onChange: (view: ReceiptsViewMode) => void }) {
  return (
    <ToggleGroup
      type="single"
      value={value}
      onValueChange={(next) => {
        if (next === 'table' || next === 'timeline') onChange(next)
      }}
      aria-label="Receipts view"
      className="rounded-sm border border-input"
      data-testid="receipts-view-toggle"
    >
      <ToggleGroupItem value="table" aria-label="Table view" className="h-7 gap-1 px-2 text-xs">
        <Table2 className="size-3.5" aria-hidden="true" />
        Table
      </ToggleGroupItem>
      <ToggleGroupItem value="timeline" aria-label="Timeline view" className="h-7 gap-1 px-2 text-xs">
        <LayoutList className="size-3.5" aria-hidden="true" />
        Timeline
      </ToggleGroupItem>
    </ToggleGroup>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Export menu (JSON / CSV — the filtered set)
// ─────────────────────────────────────────────────────────────────────────────

export function ExportMenu({ onExport, disabled }: { onExport: (format: 'json' | 'csv') => void; disabled?: boolean }) {
  return (
    <DropdownMenu>
      <Tooltip content="Export the filtered set">
        <DropdownMenuTrigger
          aria-label="Export receipts"
          disabled={disabled}
          className="inline-flex min-h-7 min-w-7 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground disabled:pointer-events-none disabled:opacity-50"
          data-testid="receipts-export-menu"
        >
          <Download className="size-4" aria-hidden="true" />
        </DropdownMenuTrigger>
      </Tooltip>
      <DropdownMenuContent align="end" className="bg-surface">
        <DropdownMenuItem onSelect={() => onExport('json')} data-testid="receipts-export-json">
          Export as JSON
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onExport('csv')} data-testid="receipts-export-csv">
          Export as CSV
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// The bar (desktop) + filter sheet (mobile)
// ─────────────────────────────────────────────────────────────────────────────

export interface ReceiptsFilterBarProps {
  filter: ReceiptsViewFilter
  onFilterChange: (patch: Partial<ReceiptsViewFilter>) => void
  onClearFilters: () => void
  onExport: (format: 'json' | 'csv') => void
  exportDisabled?: boolean
  searchInputRef: React.RefObject<HTMLInputElement | null>
  isMobile: boolean
}

export function ReceiptsFilterBar({
  filter,
  onFilterChange,
  onClearFilters,
  onExport,
  exportDisabled,
  searchInputRef,
  isMobile,
}: ReceiptsFilterBarProps) {
  const [sheetOpen, setSheetOpen] = useState(false)
  const count = activeFilterCount(filter)

  const facets = (
    <>
      <FacetSelect
        label="Filter by result"
        value={filter.result}
        options={RESULT_OPTIONS}
        onChange={(result) => onFilterChange({ result: result as ReceiptsViewFilter['result'] })}
        testId="receipts-filter-result"
      />
      <FacetSelect
        label="Filter by action type"
        value={filter.actionKind}
        options={ACTION_OPTIONS}
        onChange={(actionKind) => onFilterChange({ actionKind })}
        testId="receipts-filter-action"
      />
      <FacetSelect
        label="Filter by actor"
        value={filter.actor}
        options={ACTOR_OPTIONS}
        onChange={(actor) => onFilterChange({ actor: actor as ReceiptsViewFilter['actor'] })}
        testId="receipts-filter-actor"
      />
      <FacetSelect
        label="Filter by date range"
        value={filter.dateRange}
        options={DATE_OPTIONS}
        onChange={(dateRange) => onFilterChange({ dateRange: dateRange as ReceiptDateRange })}
        testId="receipts-filter-date"
      />
    </>
  )

  if (isMobile) {
    return (
      <div className="flex h-11 shrink-0 items-center gap-2 border-b border-border bg-surface px-3" data-testid="receipts-filter-bar">
        <ReceiptSearchInput value={filter.query} onChange={(query) => onFilterChange({ query })} inputRef={searchInputRef} className="min-w-0 flex-1" />
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => setSheetOpen(true)}
          aria-label={count > 0 ? `Filters — ${count} active` : 'Filters'}
          className="h-7 gap-1.5 rounded-sm px-2 text-xs"
          data-testid="receipts-filter-button"
        >
          <ListFilter className="size-3.5" aria-hidden="true" />
          Filter
          {count > 0 ? (
            <span className="inline-flex min-w-4 items-center justify-center rounded-sm bg-accent-soft px-1 text-[11px] font-semibold text-accent-soft-text" aria-hidden="true">
              {count}
            </span>
          ) : null}
        </Button>
        <ExportMenu onExport={onExport} disabled={exportDisabled} />

        <Drawer open={sheetOpen} onOpenChange={setSheetOpen} title="Filter receipts" width={420}>
          <div className="flex flex-col gap-4" data-testid="receipts-filter-sheet">
            <div className="flex flex-col gap-1.5">
              <span className="text-xs font-medium text-foreground-secondary">View</span>
              <ViewToggle value={filter.view} onChange={(view) => onFilterChange({ view })} />
            </div>
            <div className="flex flex-col gap-1.5">
              <span className="text-xs font-medium text-foreground-secondary">Filters</span>
              <div className="flex flex-wrap gap-2">{facets}</div>
            </div>
            <label className="flex min-h-10 items-center gap-2 text-sm text-foreground">
              <input
                type="checkbox"
                checked={filter.groupRelated}
                onChange={(e) => onFilterChange({ groupRelated: e.target.checked })}
                className="size-4 accent-[var(--accent)]"
              />
              Group related receipts (timeline)
            </label>
            {count > 0 ? (
              <Button type="button" variant="ghost" size="sm" onClick={onClearFilters} className="self-start">
                Clear filters
              </Button>
            ) : null}
          </div>
        </Drawer>
      </div>
    )
  }

  return (
    <div className="flex h-11 shrink-0 flex-wrap items-center gap-2 border-b border-border bg-surface px-3" data-testid="receipts-filter-bar">
      <ReceiptSearchInput value={filter.query} onChange={(query) => onFilterChange({ query })} inputRef={searchInputRef} className="w-56" />
      {facets}
      <div className="flex-1" />
      <GroupRelatedToggle checked={filter.groupRelated} onChange={(groupRelated) => onFilterChange({ groupRelated })} />
      <ViewToggle value={filter.view} onChange={(view) => onFilterChange({ view })} />
      <ExportMenu onExport={onExport} disabled={exportDisabled} />
    </div>
  )
}

function GroupRelatedToggle({ checked, onChange }: { checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <Tooltip content="Chain approval → run → validate receipts in the timeline">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label="Group related receipts"
        onClick={() => onChange(!checked)}
        className={cn(
          'inline-flex h-7 items-center gap-1.5 rounded-sm border px-2 text-xs transition-colors duration-instant',
          checked ? 'border-accent/40 bg-accent-soft text-accent-soft-text' : 'border-input text-foreground-secondary hover:bg-hover',
        )}
        data-testid="receipts-group-toggle"
      >
        <Check className={cn('size-3.5', checked ? 'opacity-100' : 'opacity-30')} aria-hidden="true" />
        Group related
      </button>
    </Tooltip>
  )
}
