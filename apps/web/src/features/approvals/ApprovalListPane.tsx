/**
 * ApprovalListPane — the inbox list column (approvals.md): FilterBar (search,
 * facet chips for risk / application / operation type / expiring soon, sort),
 * pending-vs-decided toggle, and ApprovalCard rows (3-line: risk badge, plain
 * action title, instance + age/expiry, chevron). Selected row: accent-soft.
 */
import { formatDistanceToNowStrict, parseISO } from 'date-fns'
import { ArrowDownWideNarrow, ChevronRight, ListFilter, Search, ShieldCheck, TriangleAlert } from 'lucide-react'
import { useMemo } from 'react'

import type { ApplicationInstance, Approval, RiskLevel } from '@/client'
import { EmptyState, ErrorState, SkeletonRows, StatusBadge, TimeAgo } from '@/components'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'

import {
  activeFacetCount,
  approvalRowDomId,
  approvalStatusPresentation,
  expiryText,
  isExpired,
  isExpiryUrgent,
  operationTypesOf,
  riskPresentation,
} from './approvalsModel'
import type { ApprovalFilters, ApprovalSort, ApprovalView } from './approvalsModel'

const RISKS: RiskLevel[] = ['low', 'medium', 'high']

function ApprovalRow({
  approval,
  view,
  selected,
  instanceName,
  onSelect,
  now,
}: {
  approval: Approval
  view: ApprovalView
  selected: boolean
  instanceName: string | undefined
  onSelect: (id: string) => void
  now: number
}) {
  const risk = riskPresentation(approval.risk)
  const status = approvalStatusPresentation(approval.status)
  const expired = isExpired(approval, now)
  const urgent = isExpiryUrgent(approval, now)
  const distance = approval.expiresAt ? formatDistanceToNowStrict(parseISO(approval.expiresAt)) : ''
  const expiry = expiryText(approval, distance, now)

  return (
    <li>
      <button
        type="button"
        id={approvalRowDomId(approval.id)}
        onClick={() => onSelect(approval.id)}
        aria-current={selected ? 'true' : undefined}
        className={cn(
          'flex w-full flex-col gap-0.5 border-b border-border px-3 py-2 text-left transition-colors duration-instant',
          'min-h-16 focus-visible:outline-2 focus-visible:outline-focus',
          selected ? 'bg-accent-soft' : 'hover:bg-hover',
        )}
        data-testid="approval-row"
        data-risk={approval.risk}
      >
        <span className="flex items-center gap-2">
          {view === 'pending' ? (
            <StatusBadge state={risk.state} label={risk.label} icon={risk.icon} />
          ) : (
            <StatusBadge state={status.state} label={status.label} icon={status.icon} />
          )}
          <span className="ml-auto shrink-0">
            <TimeAgo date={approval.status === 'pending' ? approval.requestedAt : (approval.decidedAt ?? approval.requestedAt)} />
          </span>
        </span>
        <span className="truncate text-sm font-medium text-foreground">{approval.title}</span>
        <span className="flex items-center gap-1.5 text-xs text-foreground-secondary">
          <span className="min-w-0 truncate">{instanceName ?? approval.instanceId}</span>
          <span aria-hidden="true">·</span>
          {expired ? (
            <span className="shrink-0 text-foreground-tertiary">Expired</span>
          ) : approval.status === 'pending' ? (
            <span className={cn('flex shrink-0 items-center gap-1', urgent && 'text-status-attention')}>
              {urgent ? <TriangleAlert className="size-3" aria-hidden="true" /> : null}
              {expiry}
            </span>
          ) : (
            <span className="shrink-0 truncate text-foreground-tertiary">{approval.operationType}</span>
          )}
          <ChevronRight className="ml-auto size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
        </span>
      </button>
    </li>
  )
}

export interface ApprovalListPaneProps {
  /** Filtered + sorted rows for the current view. */
  approvals: Approval[]
  /** Unfiltered inbox — the source for facet options (operation types). */
  facetSource: Approval[]
  loading: boolean
  error: unknown
  onRetry: () => void
  filters: ApprovalFilters
  onFiltersChange: (filters: ApprovalFilters) => void
  sort: ApprovalSort
  onSortChange: (sort: ApprovalSort) => void
  instances: ApplicationInstance[]
  /** Unfiltered pending count for the header + toggle. */
  pendingCount: number
  decidedCount: number
  selectedId?: string
  onSelect: (id: string) => void
  now: number
}

export function ApprovalListPane({
  approvals,
  facetSource,
  loading,
  error,
  onRetry,
  filters,
  onFiltersChange,
  sort,
  onSortChange,
  instances,
  pendingCount,
  decidedCount,
  selectedId,
  onSelect,
  now,
}: ApprovalListPaneProps) {
  const operationTypes = useMemo(() => operationTypesOf(facetSource), [facetSource])
  const instanceNameById = useMemo(() => {
    const map = new Map<string, string>()
    for (const i of instances) map.set(i.id, i.name)
    return (id: string) => map.get(id)
  }, [instances])

  const facets = activeFacetCount(filters)
  const filtering = filters.query.trim() !== '' || facets > 0

  return (
    <div className="flex min-h-0 flex-1 flex-col" data-testid="approval-list-pane">
      {/* FilterBar */}
      <div className="flex flex-col gap-2 border-b border-border px-3 py-2">
        <div className="flex items-center gap-2">
          <div className="relative min-w-0 flex-1">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-foreground-tertiary"
              aria-hidden="true"
            />
            <Input
              type="search"
              placeholder="Search approvals…"
              aria-label="Search approvals"
              value={filters.query}
              onChange={(e) => onFiltersChange({ ...filters, query: e.target.value })}
              onKeyDown={(e) => {
                if (e.key === 'Escape' && filters.query) {
                  e.stopPropagation()
                  onFiltersChange({ ...filters, query: '' })
                }
              }}
              className="h-control-sm pl-8"
            />
          </div>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" aria-label="Filter approvals">
                <ListFilter aria-hidden="true" />
                <span className="hidden sm:inline">Filters</span>
                {facets > 0 ? (
                  <span className="inline-flex min-w-5 items-center justify-center rounded-sm bg-accent-soft px-1 text-xs font-semibold text-accent-soft-text">
                    {facets}
                  </span>
                ) : null}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64">
              <DropdownMenuLabel>Risk</DropdownMenuLabel>
              {RISKS.map((level) => {
                const p = riskPresentation(level)
                return (
                  <DropdownMenuCheckboxItem
                    key={level}
                    checked={filters.risks.includes(level)}
                    onSelect={(e) => e.preventDefault()}
                    onCheckedChange={(checked) =>
                      onFiltersChange({
                        ...filters,
                        risks: checked ? [...filters.risks, level] : filters.risks.filter((r) => r !== level),
                      })
                    }
                    data-testid={`filter-risk-${level}`}
                  >
                    {p.label}
                  </DropdownMenuCheckboxItem>
                )
              })}
              <DropdownMenuSeparator />
              <DropdownMenuLabel>Application</DropdownMenuLabel>
              <DropdownMenuRadioGroup
                value={filters.instanceId ?? ''}
                onValueChange={(value) => onFiltersChange({ ...filters, instanceId: value || null })}
              >
                <DropdownMenuRadioItem value="">All applications</DropdownMenuRadioItem>
                {instances.map((instance) => (
                  <DropdownMenuRadioItem key={instance.id} value={instance.id}>
                    {instance.name}
                  </DropdownMenuRadioItem>
                ))}
              </DropdownMenuRadioGroup>
              {operationTypes.length > 0 ? (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuLabel>Operation type</DropdownMenuLabel>
                  <DropdownMenuRadioGroup
                    value={filters.operationType ?? ''}
                    onValueChange={(value) => onFiltersChange({ ...filters, operationType: value || null })}
                  >
                    <DropdownMenuRadioItem value="">All operations</DropdownMenuRadioItem>
                    {operationTypes.map((type) => (
                      <DropdownMenuRadioItem key={type} value={type}>
                        {type}
                      </DropdownMenuRadioItem>
                    ))}
                  </DropdownMenuRadioGroup>
                </>
              ) : null}
              <DropdownMenuSeparator />
              <DropdownMenuCheckboxItem
                checked={filters.expiringSoon}
                onCheckedChange={(checked) => onFiltersChange({ ...filters, expiringSoon: checked === true })}
              >
                Expiring soon (under 12 h)
              </DropdownMenuCheckboxItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" aria-label="Sort approvals">
                <ArrowDownWideNarrow aria-hidden="true" />
                <span className="hidden sm:inline">
                  {sort === 'newest' ? 'Newest' : sort === 'risk' ? 'Risk' : 'Expiring'}
                </span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Sort</DropdownMenuLabel>
              <DropdownMenuRadioGroup value={sort} onValueChange={(v) => onSortChange(v as ApprovalSort)}>
                <DropdownMenuRadioItem value="newest">Newest first</DropdownMenuRadioItem>
                <DropdownMenuRadioItem value="risk">Risk — most dangerous first</DropdownMenuRadioItem>
                <DropdownMenuRadioItem value="expiring">Expiring soonest first</DropdownMenuRadioItem>
              </DropdownMenuRadioGroup>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        {/* Pending / decided toggle */}
        <div role="group" aria-label="Approval status" className="flex items-center gap-1">
          {(['pending', 'decided'] as const).map((view) => (
            <button
              key={view}
              type="button"
              aria-pressed={filters.view === view}
              onClick={() => onFiltersChange({ ...filters, view })}
              className={cn(
                'rounded-sm px-2 py-1 text-xs font-medium transition-colors duration-instant',
                filters.view === view
                  ? 'bg-active text-foreground'
                  : 'text-foreground-secondary hover:bg-hover hover:text-foreground',
              )}
              data-testid={`view-${view}`}
            >
              {view === 'pending' ? `Pending${pendingCount > 0 ? ` (${pendingCount})` : ''}` : `Decided${decidedCount > 0 ? ` (${decidedCount})` : ''}`}
            </button>
          ))}
        </div>
      </div>

      {/* List */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {loading ? (
          <SkeletonRows rows={4} />
        ) : error ? (
          <ErrorState
            title="Approvals couldn't be loaded"
            error={error}
            preservedNote="No decisions were made."
            onRetry={onRetry}
          />
        ) : approvals.length === 0 ? (
          filters.view === 'pending' && !filtering ? (
            <EmptyState
              icon={ShieldCheck}
              title="No pending approvals"
              description="Actions that need your confirmation will appear here before they change an application."
              secondaryAction={
                decidedCount > 0
                  ? { label: 'View decided approvals', onClick: () => onFiltersChange({ ...filters, view: 'decided' }) }
                  : undefined
              }
            />
          ) : (
            <EmptyState
              icon={ShieldCheck}
              title={filters.view === 'pending' ? 'No approvals match' : 'No decided approvals'}
              description={
                filters.view === 'pending'
                  ? 'No pending request matches the current search and filters.'
                  : 'Decisions you have already made will appear here with their receipts.'
              }
              action={
                filtering
                  ? {
                      label: 'Clear filters',
                      onClick: () => onFiltersChange({ ...filters, query: '', risks: [], instanceId: null, operationType: null, expiringSoon: false }),
                    }
                  : undefined
              }
            />
          )
        ) : (
          <ul aria-label={filters.view === 'pending' ? 'Pending approvals' : 'Decided approvals'} data-testid="approval-list">
            {approvals.map((approval) => (
              <ApprovalRow
                key={approval.id}
                approval={approval}
                view={filters.view}
                selected={approval.id === selectedId}
                instanceName={instanceNameById(approval.instanceId)}
                onSelect={onSelect}
                now={now}
              />
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
