import { Link } from 'react-router-dom'
import { useSessionStore } from '@/state'
import { SetupStatus } from './SetupStatus'

interface Control {
  to: string
  title: string
  detail: string
  /** Shown only to the platform operator role, which the service requires. */
  operatorOnly?: boolean
}

// Only pages that work in this release are listed. The operator-only pages
// appear for the role that can use them and are otherwise left out, so the hub
// never links to a page that would only refuse the session.
const controls: Control[] = [
  { to: '/settings/models', title: 'AI model', detail: 'Choose the model StatePort uses and check that it answers.' },
  { to: '/execution-host', title: 'Execution host', detail: 'Read-only status of the runtime that carries out approved work.' },
  { to: '/authority', title: 'Standing authority', detail: 'Review granted authority; pause or revoke it.', operatorOnly: true },
  { to: '/updater', title: 'Installed updater', detail: 'Read-only update policy and rollback availability.', operatorOnly: true },
  { to: '/settings/advanced', title: 'Diagnostics', detail: 'Service connection settings and a copyable diagnostic snapshot.' },
]

export default function PlatformPage() {
  const status = useSessionStore((s) => s.serviceStatus)
  const operator = status?.actor?.platformOperationsAllowed === true
  const visible = controls.filter((control) => !control.operatorOnly || operator)
  return (
    <div className="h-full overflow-auto bg-app p-4 md:p-6" data-testid="platform-page">
      <div className="mx-auto flex max-w-5xl flex-col gap-5">
        <header>
          <h1 className="text-xl font-semibold text-foreground">Platform</h1>
          <p className="mt-1 text-sm text-foreground-secondary">Check that StatePort is ready, then open the status page you need.</p>
        </header>
        <SetupStatus includeRuntime />
        <nav aria-label="Platform controls" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {visible.map((control) => (
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
