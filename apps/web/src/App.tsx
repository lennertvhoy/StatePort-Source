/**
 * StatePort router (design.md §12). HashRouter; every primary route is lazy
 * with a skeleton Suspense fallback. Titles are managed by TitleManager.
 *
 *   #/applications
 *   #/catalog
 *   #/sources · #/sources/:sourceId
 *   #/statebench
 *   #/deployments · #/authority · #/updater · #/preview-routes
 *   #/approvals · #/approvals/:approvalId
 *   #/settings · #/settings/:group
 *   #/app/:instanceId  (Overview)
 *   #/app/:instanceId/conversation
 *   #/app/:instanceId/runs
 *   #/app/:instanceId/settings
 *   #/app/:instanceId/receipts
 *   #/app/:instanceId/receipts/:receiptId
 *   #/app/:instanceId/workbench  (Overview tool)
 *   #/app/:instanceId/workbench/{files,terminal,deployments,orchestration,receipts}
 *   #/app/:instanceId/workbench/receipts/:receiptId
 */
import { Compass } from 'lucide-react'
import type { ComponentType, LazyExoticComponent, ReactNode } from 'react'
import { lazy, Suspense } from 'react'
import { HashRouter, Navigate, Route, Routes } from 'react-router-dom'

import { EmptyState, SkeletonRows } from '@/components'
import { ApplicationViewGuard } from '@/features/application-experience/ApplicationViewGuard'
import type { ApplicationDestination } from '@/features/application-experience/registry'
import { AppShell } from '@/shell/AppShell'
import { AppContextShell } from '@/shell/AppContextShell'

// ── Lazy feature surfaces ────────────────────────────────────────────────────

const WorkbenchIntegrations = lazy(() =>
  import('@/features/workbench/WorkbenchIntegrations').then((module) => ({
    default: module.WorkbenchIntegrations,
  })),
)
const ApplicationsPage = lazy(() => import('@/features/applications/ApplicationsPage'))
const CatalogPage = lazy(() => import('@/features/catalog/CatalogPage'))
const SourceRegistryPage = lazy(() => import('@/features/sources/SourceRegistryPage'))
const PlatformStateBenchPage = lazy(() => import('@/features/statebench/PlatformStateBenchPage'))
const PlatformDeploymentsPage = lazy(() => import('@/features/platform-deployments/PlatformDeploymentsPage'))
const AuthorityPage = lazy(() => import('@/features/authority/AuthorityPage'))
const UpdaterPage = lazy(() => import('@/features/updater/UpdaterPage'))
const PreviewRoutesPage = lazy(() => import('@/features/preview-routes/PreviewRoutesPage'))
const ApprovalsPage = lazy(() => import('@/features/approvals/ApprovalsPage'))
const SettingsPage = lazy(() => import('@/features/settings/SettingsPage'))
const AppOverviewPage = lazy(() => import('@/features/app-overview/AppOverviewPage'))
const ConversationPage = lazy(() => import('@/features/conversation/ConversationPage'))
const RunsPage = lazy(() => import('@/features/runs/RunsPage'))
const ExecutionHostPage = lazy(() => import('@/features/execution-host/ExecutionHostPage'))
const ApplicationReceiptPage = lazy(() => import('@/features/receipts/ApplicationReceiptPage'))
const ApplicationReceiptsPage = lazy(() => import('@/features/receipts/ApplicationReceiptsPage'))
const WorkbenchOverviewTool = lazy(() => import('@/features/workbench/WorkbenchOverviewTool'))
const FilesTool = lazy(() => import('@/features/files/FilesTool'))
const TerminalTool = lazy(() => import('@/features/terminal/TerminalTool'))
const DeploymentsTool = lazy(() => import('@/features/infrastructure/DeploymentsTool'))
const OrchestrationTool = lazy(() => import('@/features/orchestration/OrchestrationTool'))
const ReceiptsTool = lazy(() => import('@/features/receipts/ReceiptsTool'))

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
          <Route index element={<Navigate to="/applications" replace />} />
          <Route path="applications" element={page(ApplicationsPage)} />
          <Route path="catalog" element={page(CatalogPage)} />
          <Route path="sources" element={page(SourceRegistryPage)} />
          <Route path="sources/:sourceId" element={page(SourceRegistryPage)} />
          <Route path="statebench" element={page(PlatformStateBenchPage)} />
          <Route path="execution-host" element={page(ExecutionHostPage)} />
          <Route path="deployments" element={page(PlatformDeploymentsPage)} />
          <Route path="authority" element={page(AuthorityPage)} />
          <Route path="updater" element={page(UpdaterPage)} />
          <Route path="preview-routes" element={page(PreviewRoutesPage)} />
          <Route path="approvals" element={page(ApprovalsPage)} />
          <Route path="approvals/:approvalId" element={page(ApprovalsPage)} />
          <Route path="settings" element={page(SettingsPage)} />
          <Route path="settings/:group" element={page(SettingsPage)} />
          <Route path="app/:instanceId" element={<AppContextShell />}>
            <Route index element={page(AppOverviewPage)} />
            <Route
              path="conversation"
              element={applicationView('conversation', page(ConversationPage))}
            />
            <Route path="runs" element={applicationView('runs', page(RunsPage))} />
            <Route path="settings" element={page(SettingsPage)} />
            <Route
              path="receipts"
              element={applicationView('receipts', page(ApplicationReceiptsPage))}
            />
            <Route
              path="receipts/:receiptId"
              element={applicationView('receipts', page(ApplicationReceiptPage))}
            />
            <Route
              path="workbench"
              element={applicationView('workbench', page(WorkbenchIntegrations))}
            >
              <Route index element={page(WorkbenchOverviewTool)} />
              <Route path="files" element={page(FilesTool)} />
              <Route path="terminal" element={page(TerminalTool)} />
              <Route path="deployments" element={page(DeploymentsTool)} />
              <Route path="orchestration" element={page(OrchestrationTool)} />
              <Route path="receipts" element={page(ReceiptsTool)} />
              <Route path="receipts/:receiptId" element={page(ReceiptsTool)} />
            </Route>
          </Route>
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </HashRouter>
  )
}
