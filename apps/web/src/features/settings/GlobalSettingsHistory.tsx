/**
 * Bounded backend-owned global settings history.
 *
 * The source is GET /v1/settings.recentReceipts. Browser presentation
 * preferences are intentionally absent and survive a backend rollback.
 */
import { History, RotateCcw } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

import type {
  GlobalSettings,
  GlobalSettingsRollbackHistory,
  GlobalSettingsRollbackTarget,
} from '@/client'
import { getClient } from '@/client'
import { ConfirmDialog, InlineNotice } from '@/components'
import { Button } from '@/components/ui/button'
import { useSessionStore } from '@/state'

import { SettingSubsection } from './controls'

const FIELD_LABELS: Record<string, string> = {
  'general.appearance': 'Appearance',
  'general.defaultLandingView': 'Default landing view',
  'notifications.level': 'Notification level',
}

function fieldLabel(key: string): string {
  return FIELD_LABELS[key] ?? key
}

function valueLabel(value: string | number | boolean): string {
  if (typeof value === 'boolean') return value ? 'On' : 'Off'
  return String(value).replaceAll('_', ' ')
}

function targetEffect(target: GlobalSettingsRollbackTarget): string {
  return Object.keys(target.previousValues)
    .map((key) => {
      const current = target.changes[key]
      const previous = target.previousValues[key]
      return `${fieldLabel(key)} (${key}): ${valueLabel(current)} → ${valueLabel(previous)}`
    })
    .join('; ')
}

export function GlobalSettingsHistory({
  replaceAll,
  refreshToken,
}: {
  replaceAll: (next: GlobalSettings) => void
  refreshToken: number
}) {
  const pushToast = useSessionStore((state) => state.pushToast)
  const [history, setHistory] = useState<GlobalSettingsRollbackHistory | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [rollbackError, setRollbackError] = useState<string | null>(null)
  const [selected, setSelected] = useState<GlobalSettingsRollbackTarget | null>(null)
  const [reloadNonce, setReloadNonce] = useState(0)

  useEffect(() => {
    let cancelled = false
    getClient()
      .globalSettings.getRollbackHistory()
      .then((result) => {
        if (cancelled) return
        setHistory(result)
        setLoadError(null)
      })
      .catch((error: unknown) => {
        if (cancelled) return
        setHistory(null)
        setLoadError(error instanceof Error ? error.message : 'Settings history could not be loaded')
      })
    return () => {
      cancelled = true
    }
  }, [refreshToken, reloadNonce])

  const exactEffect = useMemo(
    () => (selected ? targetEffect(selected) : ''),
    [selected],
  )

  const reload = () => {
    setHistory(null)
    setLoadError(null)
    setRollbackError(null)
    setReloadNonce((value) => value + 1)
  }

  return (
    <SettingSubsection
      title="Backend settings history"
      description="Only durable, backend-owned global mutations appear here. Browser-only presentation preferences—layout, editor, terminal, accessibility, and similar UI choices—are local and are not rolled back."
    >
      <div
        id="setting-backend-settings-history"
        data-setting-anchor="backend-settings-history"
        className="scroll-mt-24 py-2"
        data-testid="global-settings-history"
      >
        {rollbackError ? (
          <InlineNotice tone="danger" title="Rollback refused" className="mb-2">
            <span>{rollbackError}</span>
            <Button variant="outline" size="sm" className="mt-2" onClick={reload}>
              Reload current history
            </Button>
          </InlineNotice>
        ) : null}
        {loadError ? (
          <InlineNotice tone="danger" title="Settings history unavailable">
            <span>{loadError}</span>
            <Button variant="outline" size="sm" className="mt-2" onClick={reload}>
              Retry
            </Button>
          </InlineNotice>
        ) : history === null ? (
          <p className="text-xs text-foreground-secondary">Loading backend settings history…</p>
        ) : (
          <>
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs text-foreground-secondary">
                Current backend revision{' '}
                <span className="tnum font-mono text-foreground">{history.currentRevision}</span>
              </p>
              <Button variant="ghost" size="sm" onClick={reload}>
                <History className="size-3.5" aria-hidden="true" />
                Refresh
              </Button>
            </div>
            {history.targets.length === 0 ? (
              <p className="rounded-sm border border-border bg-sunken px-3 py-2 text-xs text-foreground-secondary">
                No rollback-capable backend settings mutations have been recorded.
              </p>
            ) : (
              <ol className="flex flex-col divide-y divide-border/60 rounded-sm border border-border" data-testid="global-settings-history-list">
                {history.targets.map((target) => (
                  <li key={target.receiptId} className="flex flex-wrap items-center justify-between gap-3 px-3 py-2.5">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-foreground">
                        {target.action === 'settings.rollback'
                          ? 'Backend settings rollback'
                          : 'Backend settings change'}
                      </p>
                      <p className="mt-0.5 text-xs text-foreground-secondary">
                        Revision <span className="tnum font-mono">{target.revision}</span>
                        {' · '}
                        {Object.keys(target.changes).map(fieldLabel).join(', ')}
                      </p>
                      <p className="mt-0.5 break-all font-mono text-code text-foreground-tertiary">
                        Receipt {target.receiptId}
                      </p>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setRollbackError(null)
                        setSelected(target)
                      }}
                      data-testid={`settings-rollback-${target.receiptId}`}
                    >
                      <RotateCcw className="size-3.5" aria-hidden="true" />
                      Review rollback
                    </Button>
                  </li>
                ))}
              </ol>
            )}
          </>
        )}
      </div>

      <ConfirmDialog
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelected(null)
        }}
        title="Roll back backend-owned global settings?"
        description={
          selected && history
            ? `Use current backend revision ${history.currentRevision} to reverse the exact change recorded at revision ${selected.revision}. Browser-only preferences and application settings are not affected.`
            : undefined
        }
        target={
          selected
            ? `Global settings receipt ${selected.receiptId} (revision ${selected.revision})`
            : undefined
        }
        effect={exactEffect}
        reversibility="This creates a new settings.rollback receipt. It does not erase either mutation from history."
        confirmLabel="Roll back this receipt"
        onConfirm={async () => {
          if (!selected || !history) return
          try {
            const next = await getClient().globalSettings.rollback({
              expectedRevision: history.currentRevision,
              receiptId: selected.receiptId,
            })
            replaceAll(next)
            const refreshed = await getClient().globalSettings.getRollbackHistory()
            setHistory(refreshed)
            setRollbackError(null)
            pushToast({
              kind: 'success',
              title: 'Backend settings rolled back',
              body: `Receipt ${selected.receiptId} was reversed at revision ${refreshed.currentRevision}.`,
            })
          } catch (error) {
            setRollbackError(
              error instanceof Error
                ? error.message
                : 'The rollback was refused; reload the current settings history.',
            )
          }
        }}
      />
    </SettingSubsection>
  )
}
