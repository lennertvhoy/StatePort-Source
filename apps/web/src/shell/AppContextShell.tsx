/**
 * AppContextShell — loads the application instance via client.applications
 * and provides `useCurrentInstance()` to every app-level route. Renders the
 * app-level nav (Overview · Conversation · Runs-if-capability ·
 * Workbench-if-capability · Receipts-if-capability · Settings) and honest
 * loading / not-found states.
 */
import { CirclePlay, LayoutDashboard, MessageSquare, Receipt, Settings, Wrench } from 'lucide-react'
import type { ReactNode } from 'react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { NavLink, Outlet, useLocation, useParams } from 'react-router-dom'

import type { ApplicationInstance, CapabilityId, CapabilityState } from '@/client'
import { ClientError } from '@/client'
import { ErrorState, InlineNotice, SkeletonRows } from '@/components'
import {
  applicationNavigation,
  type ApplicationNavIcon,
} from '@/features/application-experience/registry'
import { cn } from '@/lib/utils'

import type { CurrentInstanceContext } from './currentInstance'
import { InstanceContext } from './currentInstance'
import { fetchInstanceCached, primeInstanceCache, useMarkLastOpened } from './data'

const NAV_ICONS: Record<ApplicationNavIcon, typeof LayoutDashboard> = {
  overview: LayoutDashboard,
  conversation: MessageSquare,
  runs: CirclePlay,
  workbench: Wrench,
  receipts: Receipt,
  settings: Settings,
}

export function AppContextShell({ children }: { children?: ReactNode }) {
  const { instanceId } = useParams<{ instanceId: string }>()
  const location = useLocation()
  // Keep the last result for this instance mounted while a refresh is in flight.
  // Switching instances still fails closed to the loading surface.
  const [result, setResult] = useState<{
    key: string
    instanceId: string
    instance: ApplicationInstance | null
    error: unknown
  } | null>(null)
  const [nonce, setNonce] = useState(0)

  const refresh = useCallback(() => setNonce((n) => n + 1), [])
  const requestKey = `${instanceId ?? ''}#${nonce}`

  useEffect(() => {
    if (!instanceId) return
    let cancelled = false
    fetchInstanceCached(instanceId)
      .then((loaded) => {
        if (cancelled) return
        primeInstanceCache(loaded)
        setResult({ key: requestKey, instanceId, instance: loaded, error: null })
      })
      .catch((err) => {
        if (cancelled) return
        setResult({ key: requestKey, instanceId, instance: null, error: err })
      })
    return () => {
      cancelled = true
    }
  }, [instanceId, nonce, requestKey])

  const current = result?.instanceId === instanceId ? result : null
  const loading = Boolean(instanceId) && !current
  const instance = current?.instance ?? null
  const error = current?.error ?? null

  const capabilities = useMemo<ReadonlyMap<CapabilityId, CapabilityState>>(
    () => new Map((instance?.capabilities ?? []).map((c) => [c.id, c])),
    [instance],
  )

  const hasCapability = useCallback(
    (id: CapabilityId) => {
      const state = capabilities.get(id)
      return state?.status === 'available' || state?.status === 'degraded'
    },
    [capabilities],
  )

  const capability = useCallback((id: CapabilityId) => capabilities.get(id), [capabilities])
  const navigation = useMemo(
    () => (instance ? applicationNavigation(instance) : []),
    [instance],
  )

  const view = location.pathname.split('/').filter(Boolean)[2] ?? 'overview'
  useMarkLastOpened(instanceId, view)

  const value = useMemo<CurrentInstanceContext>(
    () => ({ instance, capabilities, loading, error, refresh, hasCapability, capability }),
    [instance, capabilities, loading, error, refresh, hasCapability, capability],
  )

  if (!instanceId) {
    return <ErrorState title="No application selected" error="This route needs an application id." />
  }

  if (loading) {
    return (
      <div className="flex h-full flex-col" data-testid="app-loading">
        <div className="h-9 border-b border-border bg-surface" />
        <SkeletonRows rows={5} className="p-4" />
      </div>
    )
  }

  if (error || !instance) {
    const notFound = error instanceof ClientError && error.status === 404
    return (
      <div className="flex h-full flex-col items-center justify-center p-6">
        <ErrorState
          title={notFound ? 'Application not found' : 'Could not load the application'}
          error={
            notFound
              ? `No application with id “${instanceId}” exists. It may have been removed.`
              : error ?? 'The application projection was unavailable.'
          }
          preservedNote="Nothing was changed."
          onRetry={refresh}
          retryLabel="Retry"
        />
      </div>
    )
  }

  const note = (location.state as { note?: string } | null)?.note

  return (
    <InstanceContext.Provider value={value}>
      <div className="flex h-full flex-col" data-testid="app-context-shell">
        <nav aria-label="Application" className="flex h-9 shrink-0 items-center gap-1 overflow-x-auto border-b border-border bg-surface px-3">
          {navigation.map((item) => {
            const Icon = NAV_ICONS[item.icon]
            return (
              <NavLink
                key={item.destination}
                to={`/app/${instanceId}${item.to ? `/${item.to}` : ''}`}
                end={item.end}
                data-view-source={item.source}
                className={({ isActive }) =>
                  cn(
                    'relative flex h-full shrink-0 items-center gap-1.5 px-2 text-sm font-medium transition-colors duration-instant',
                    isActive
                      ? 'text-accent after:absolute after:inset-x-1 after:bottom-0 after:h-0.5 after:bg-accent'
                      : 'text-foreground-secondary hover:text-foreground',
                  )
                }
              >
                <Icon className="size-4" aria-hidden="true" />
                {item.label}
              </NavLink>
            )
          })}
        </nav>
        {note ? (
          <div className="shrink-0 px-3 pt-2">
            <InlineNotice tone="informational">{note}</InlineNotice>
          </div>
        ) : null}
        <div className="min-h-0 flex-1 overflow-hidden">{children ?? <Outlet />}</div>
      </div>
    </InstanceContext.Provider>
  )
}
