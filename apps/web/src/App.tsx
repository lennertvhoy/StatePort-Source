/**
 * StatePort router (design.md §12). HashRouter; every primary route is lazy
 * with a skeleton Suspense fallback. Titles are managed by TitleManager.
 *
 *   #/applications
 *   #/catalog
 *   #/platform · #/execution-host (read-only runtime status)
 *   #/authority · #/updater (operator role only; they say so otherwise)
 *   #/approvals · #/approvals/:approvalId
 *   #/settings · #/settings/:group · #/settings/models (AI models) · #/settings/provider (own account)
 *   #/app/:instanceId  (Overview)
 *   #/app/:instanceId/conversation
 *   #/app/:instanceId/runs
 *   #/app/:instanceId/settings
 *   #/app/:instanceId/receipts
 *   #/app/:instanceId/receipts/:receiptId
 *
 * Only controls that perform their real effect on the installed product are
 * routed (ADR-0007 section 5). Source registry, StateBench, deployments,
 * preview routes and the application workbench (files, terminal, deployments,
 * orchestration) are not part of this release.
 */
import { Compass } from 'lucide-react'
import type { ComponentType, LazyExoticComponent, ReactNode } from 'react'
import { lazy, Suspense } from 'react'
import { HashRouter, Route, Routes } from 'react-router-dom'

import { EmptyState, SkeletonRows } from '@/components'
import { ApplicationViewGuard } from '@/features/application-experience/ApplicationViewGuard'
import type { ApplicationDestination } from '@/features/application-experience/registry'
import { AppShell } from '@/shell/AppShell'
import { AppContextShell } from '@/shell/AppContextShell'
import { StartupRoute } from '@/shell/StartupRoute'

// ── Lazy feature surfaces ────────────────────────────────────────────────────

const ProviderSettingsPage = lazy(() => import('@/features/settings/ProviderSettings').then((module) => ({ default: module.ProviderSettings })))
const ModelsPage = lazy(() => import('@/features/models/ModelsPage'))
const PlatformPage = lazy(() => import('@/shell/PlatformPage'))
const ApplicationsPage = lazy(() => import('@/features/applications/ApplicationsPage'))
const CatalogPage = lazy(() => import('@/features/catalog/CatalogPage'))
const AuthorityPage = lazy(() => import('@/features/authority/AuthorityPage'))
const UpdaterPage = lazy(() => import('@/features/updater/UpdaterPage'))
const ApprovalsPage = lazy(() => import('@/features/approvals/ApprovalsPage'))
const SettingsPage = lazy(() => import('@/features/settings/SettingsPage'))
const AppOverviewPage = lazy(() => import('@/features/app-overview/AppOverviewPage'))
const ConversationPage = lazy(() => import('@/features/conversation/ConversationPage'))
const RunsPage = lazy(() => import('@/features/runs/RunsPage'))
const ExecutionHostPage = lazy(() => import('@/features/execution-host/ExecutionHostPage'))
const ApplicationReceiptPage = lazy(() => import('@/features/receipts/ApplicationReceiptPage'))
const ApplicationReceiptsPage = lazy(() => import('@/features/receipts/ApplicationReceiptsPage'))

function RouteSkeleton() {
  return (
    <div className="flex h-full flex-col bg-app" data-testid="route-skeleton">
      <SkeletonRows rows={6} className="p-4" />
    </div>
  )
}

/** Wrap a lazy surface in the route-level Suspense skeleton. */
function page(Component: LazyExoticComponent<ComponentType>) {
  return (
    <Suspense fallback={<RouteSkeleton />}>
      <Component />
    </Suspense>
  )
}

function applicationView(destination: ApplicationDestination, children: ReactNode) {
  return (
    <ApplicationViewGuard destination={destination}>
      {children}
    </ApplicationViewGuard>
  )
}

function NotFound() {
  return (
    <div className="flex h-full items-center justify-center bg-app p-6" data-testid="not-found">
      <EmptyState
        icon={Compass}
        title="Page not found"
        description="This route does not exist. It may have moved or never existed."
        action={{ label: 'Go to Applications', onClick: () => window.location.assign('#/applications') }}
      />
    </div>
  )
}

export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<StartupRoute />} />
          <Route path="platform" element={page(PlatformPage)} />
          <Route path="applications" element={page(ApplicationsPage)} />
          <Route path="catalog" element={page(CatalogPage)} />
          <Route path="execution-host" element={page(ExecutionHostPage)} />
          <Route path="authority" element={page(AuthorityPage)} />
          <Route path="updater" element={page(UpdaterPage)} />
          <Route path="approvals" element={page(ApprovalsPage)} />
          <Route path="approvals/:approvalId" element={page(ApprovalsPage)} />
          <Route path="settings" element={page(SettingsPage)} />
          <Route path="settings/provider" element={page(ProviderSettingsPage)} />
          <Route path="settings/models" element={page(ModelsPage)} />
          <Route path="settings/:group" element={page(SettingsPage)} />
          <Route path="app/:instanceId" element={<AppContextShell />}>
            <Route index element={page(AppOverviewPage)} />
            <Route
              path="conversation"
              element={applicationView('conversation', page(ConversationPage))}
            />
            <Route path="runs" element={applicationView('runs', page(RunsPage))} />
            <Route path="settings" element={page(SettingsPage)} />
            <Route path="settings/provider" element={page(ProviderSettingsPage)} />
            <Route path="settings/models" element={page(ModelsPage)} />
            <Route
              path="receipts"
              element={applicationView('receipts', page(ApplicationReceiptsPage))}
            />
            <Route
              path="receipts/:receiptId"
              element={applicationView('receipts', page(ApplicationReceiptPage))}
            />
          </Route>
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </HashRouter>
  )
}
