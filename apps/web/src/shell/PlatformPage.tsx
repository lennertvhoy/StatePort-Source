import { Link } from 'react-router-dom'
import { useSessionStore } from '@/state'
import { ReadinessSummary } from './ReadinessSummary'

const controls = [
  { to: '/settings/provider', title: 'Provider setup', detail: 'Configure the supported provider and verify a bounded request.' },
  { to: '/execution-host', title: 'Execution host', detail: 'Inspect the runtime and manage its lifecycle.' },
  { to: '/sources', title: 'Application sources', detail: 'Import and inspect template sources and their revisions.' },
  { to: '/deployments', title: 'Platform deployments', detail: 'Inspect managed deployments and their state.' },
  { to: '/authority', title: 'Standing authority', detail: 'Review granted authority and permission boundaries.' },
  { to: '/updater', title: 'Installed updater', detail: 'Inspect updates, readiness and recovery actions.' },
  { to: '/preview-routes', title: 'Preview routes', detail: 'Inspect application preview routing.' },
  { to: '/statebench', title: 'StateBench evidence', detail: 'Inspect platform evidence when your operator role permits it.' },
  { to: '/settings/advanced', title: 'Diagnostics', detail: 'Inspect service connection settings and diagnostics.' },
]

export default function PlatformPage() {
  const status = useSessionStore((s) => s.serviceStatus)
  return (
    <div className="h-full overflow-auto bg-app p-4 md:p-6" data-testid="platform-page">
      <div className="mx-auto flex max-w-5xl flex-col gap-5">
        <header>
          <h1 className="text-xl font-semibold text-foreground">Platform</h1>
          <p className="mt-1 text-sm text-foreground-secondary">Check readiness, then open the controls you need. Each action is checked by the service.</p>
        </header>
        <ReadinessSummary />
        {status?.actor?.platformOperationsAllowed !== true && (
          <p className="text-sm text-foreground-secondary" role="status">
            {status?.actor ? 'Your session does not permit platform operations. Controls explain their requirements; opening a page does not grant authority.' : 'Platform permissions have not been confirmed. Connect to the service to check your session.'}
          </p>
        )}
        <nav aria-label="Platform controls" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {controls.map((control) => (
            <Link key={control.to} to={control.to} className="min-w-0 rounded-md border border-border bg-surface p-4 transition-colors hover:bg-hover focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent">
              <h2 className="text-sm font-semibold text-accent">{control.title}</h2>
              <p className="mt-1 text-sm text-foreground-secondary">{control.detail}</p>
            </Link>
          ))}
        </nav>
      </div>
    </div>
  )
}
