/**
 * Application-native receipt index. Receipts are an application capability,
 * not a Workbench permission, so this surface deliberately has no Workbench
 * shell or Workbench links.
 */
import { Receipt, Search } from 'lucide-react'
import { useMemo, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'

import { copyText, EmptyState, ErrorState, Skeleton } from '@/components'
import { Input } from '@/components/ui/input'
import { useIsMobile } from '@/shell/platform'
import { useSessionStore } from '@/state'

import { ReceiptDetail } from './ReceiptDetail'
import { ReceiptsTable } from './ReceiptsTable'
import { applyReceiptsFilter, defaultFilter, parseReceiptDigest } from './receiptsModel'
import type { ReceiptsViewFilter } from './receiptsModel'
import { useReceiptListKeyboard } from './useReceiptListKeyboard'
import { useReceipts } from './useReceipts'

export default function ApplicationReceiptsPage() {
  const { instanceId = '' } = useParams<{ instanceId: string }>()
  const navigate = useNavigate()
  const isMobile = useIsMobile()
  const pushToast = useSessionStore((state) => state.pushToast)
  const searchRef = useRef<HTMLInputElement>(null)
  const [filter, setFilter] = useState<ReceiptsViewFilter>(() => defaultFilter(isMobile))
  const { receipts, loading, error, refresh, newIds } = useReceipts(instanceId)
  const filtered = useMemo(() => applyReceiptsFilter(receipts, filter), [receipts, filter])
  const openReceipt = (receipt: (typeof receipts)[number]) =>
    navigate(`/app/${instanceId}/receipts/${receipt.id}`)
  const copyReceiptId = (receipt: (typeof receipts)[number]) => {
    void copyText(receipt.id).then((ok) => {
      if (ok) pushToast({ kind: 'success', title: 'Receipt ID copied', body: receipt.id })
    })
  }
  const keyboard = useReceiptListKeyboard(filtered, { onOpen: openReceipt, onCopyId: copyReceiptId })

  return (
    <div className="flex h-full min-h-0 flex-col bg-app" data-testid="application-receipts-page">
      <header className="flex shrink-0 items-center gap-3 border-b border-border bg-surface px-3 py-2">
        <Receipt className="size-4 text-foreground-secondary" aria-hidden="true" />
        <h1 className="text-sm font-semibold text-foreground">Receipts</h1>
        <span className="text-xs text-foreground-tertiary">Application history</span>
        <div className="relative ml-auto w-56 max-w-[45%]">
          <Search className="pointer-events-none absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-foreground-tertiary" aria-hidden="true" />
          <Input
            ref={searchRef}
            type="search"
            aria-label="Search receipts"
            placeholder="Search receipts..."
            value={filter.query}
            onChange={(event) => setFilter((current) => ({ ...current, query: event.target.value }))}
            className="h-8 pl-7 text-xs"
          />
        </div>
      </header>

      {loading ? (
        <div className="flex flex-col gap-2 p-4" role="status" aria-label="Loading receipts">
          {Array.from({ length: 5 }, (_, index) => <Skeleton key={index} className="h-8 w-full" />)}
        </div>
      ) : error ? (
        <ErrorState title="Receipts could not be loaded" error={error} onRetry={refresh} retryLabel="Retry" />
      ) : receipts.length === 0 ? (
        <EmptyState icon={Receipt} title="No receipts yet" description="Application changes and operational records will appear here." />
      ) : filtered.length === 0 ? (
        <EmptyState icon={Receipt} title="No receipts match" description="Try a different search." />
      ) : (
        <div className="min-h-0 flex-1">
          <ReceiptsTable
            receipts={filtered}
            keyboard={keyboard}
            onOpen={openReceipt}
            onOpenRelated={(receipt) => {
              if (receipt.relatedApprovalId) navigate(`/approvals/${receipt.relatedApprovalId}`)
              else if (receipt.relatedConversationId) navigate(`/app/${instanceId}/conversation`)
            }}
            newIds={newIds}
            sort={filter.sort}
            onToggleSort={() => setFilter((current) => ({ ...current, sort: current.sort === 'newest' ? 'oldest' : 'newest' }))}
            compact={isMobile}
            nativeRoute
          />
        </div>
      )}
    </div>
  )
}

export function ApplicationReceiptDetailPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { instanceId = '', receiptId = '' } = useParams<{ instanceId: string; receiptId: string }>()
  const rawExpectedDigest = searchParams.get('digest')
  const expectedDigest = rawExpectedDigest === null ? null : parseReceiptDigest(rawExpectedDigest)
  const digestValid = rawExpectedDigest === null || expectedDigest !== null
  if (!instanceId || !receiptId || !digestValid) {
    return (
      <div className="flex h-full items-center justify-center bg-app p-6" data-testid="application-receipt-page">
        <EmptyState
          icon={Receipt}
          title="Receipt identity is invalid"
          description="Open the receipt again from the operation that created it so its exact identity can be verified."
        />
      </div>
    )
  }
  return (
    <div className="flex h-full min-h-0 flex-col bg-app" data-testid="application-receipt-page">
      <ReceiptDetail
        instanceId={instanceId}
        receiptId={receiptId}
        expectedPayloadDigest={expectedDigest ?? undefined}
        nativeRoute
        onClose={() => navigate(`/app/${instanceId}/receipts`)}
      />
    </div>
  )
}
