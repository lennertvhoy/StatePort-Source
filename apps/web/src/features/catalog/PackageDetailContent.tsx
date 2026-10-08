/**
 * PackageDetailContent — the catalog detail drawer body (catalog.md):
 * description, capabilities, plain-language permission summary, network
 * policy, data boundaries, existing instances (jump links), version history,
 * release notes, and technical identity (package ID, raw descriptor) behind
 * the Details disclosure only.
 */
import { ArrowUpRight, FolderLock, Globe, HardDrive, SquareTerminal } from 'lucide-react'
import { Link } from 'react-router-dom'

import type { ApplicationInstance, CatalogPackage } from '@/client'
import { CopyButton, Disclosure, Tooltip } from '@/components'
import { InstanceGlyphTile } from '@/shell/appIcon'

import {
  CAPABILITY_PRESENTATION,
  networkPolicyLabel,
  releaseStatusLabel,
  reviewClassificationPresentation,
} from './catalogModel'

function FactRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-2 py-0.5">
      <dt className="w-28 shrink-0 text-xs text-foreground-secondary">{label}</dt>
      <dd className="min-w-0 text-sm text-foreground">{children}</dd>
    </div>
  )
}

export function PackageDetailContent({
  entry,
  instances,
}: {
  entry: CatalogPackage
  instances: ApplicationInstance[]
}) {
  const { pkg } = entry
  const classification = reviewClassificationPresentation(pkg)
  const rawDescriptor = JSON.stringify(pkg, null, 2)

  return (
    <div className="flex flex-col gap-5" data-testid="package-detail">
      <p className="text-sm text-foreground">{pkg.description}</p>

      {entry.installAvailable === false ? (
        <section
          aria-label="Installation unavailable"
          className="rounded-md border border-status-waiting-border bg-status-waiting-bg px-3 py-2"
        >
          <p className="text-sm font-medium text-foreground">Installation is not currently available.</p>
          <p className="mt-0.5 text-sm text-foreground-secondary">
            {entry.installUnavailableReason ?? 'The connected service did not provide an installable exact identity.'}
          </p>
        </section>
      ) : null}

      {/* Capabilities */}
      <section aria-label="Capabilities">
        <h3 className="text-sm font-semibold text-foreground">Capabilities</h3>
        <ul className="mt-1 flex flex-wrap gap-1.5">
          {pkg.capabilities.map((cap) => {
            const { label, icon: Icon } = CAPABILITY_PRESENTATION[cap]
            return (
              <li key={cap}>
                <Tooltip content={label}>
                  <span className="inline-flex items-center gap-1.5 rounded-sm border border-border bg-surface-2 px-2 py-1 text-xs text-foreground-secondary">
                    <Icon className="size-3.5" aria-hidden="true" />
                    {label}
                  </span>
                </Tooltip>
              </li>
            )
          })}
        </ul>
      </section>

      {/* Permission summary — plain language */}
      <section aria-label="Permissions">
        <h3 className="text-sm font-semibold text-foreground">Permissions, in plain language</h3>
        <dl className="mt-1 flex flex-col">
          <div className="flex items-start gap-2 py-1">
            <FolderLock className="mt-0.5 size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
            <dd className="text-sm text-foreground">{pkg.permissions.fileAccess}</dd>
          </div>
          <div className="flex items-start gap-2 py-1">
            <SquareTerminal className="mt-0.5 size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
            <dd className="text-sm text-foreground">{pkg.permissions.terminalAccess}</dd>
          </div>
          <div className="flex items-start gap-2 py-1">
            <Globe className="mt-0.5 size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
            <dd className="text-sm text-foreground">{pkg.permissions.networkAccess}</dd>
          </div>
          <div className="flex items-start gap-2 py-1">
            <HardDrive className="mt-0.5 size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
            <dd className="text-sm text-foreground">{pkg.permissions.dataOwnership}</dd>
          </div>
        </dl>
      </section>

      {/* Network + boundaries */}
      <section aria-label="Network and data boundaries">
        <dl className="flex flex-col">
          <FactRow label="Network policy">{networkPolicyLabel(pkg.networkPolicy)}</FactRow>
          <FactRow label="Data boundaries">{pkg.dataBoundaries.join(', ')}</FactRow>
          <FactRow label="Review">
            {classification.label} · {releaseStatusLabel(pkg.releaseStatus)} v{pkg.version}
          </FactRow>
          <FactRow label="Production eligibility">
            {pkg.productionEligible === true ? 'Eligible by declaration' : pkg.productionEligible === false ? 'Not eligible' : 'Not reported'}
          </FactRow>
          <FactRow label="Public-safe fixture">
            {pkg.publicSafe === true ? 'Yes' : pkg.publicSafe === false ? 'No' : 'Not reported'}
          </FactRow>
        </dl>
      </section>

      {/* Update + release notes */}
      {entry.updateAvailable ? (
        <section aria-label="Update available" className="rounded-md border border-status-informational-border bg-status-informational-bg px-3 py-2">
          <p className="text-sm font-medium text-status-informational">
            v{entry.updateAvailable.toVersion} available
          </p>
          <p className="mt-0.5 text-sm text-foreground">{entry.updateAvailable.releaseNotes}</p>
          <p className="mt-1 text-xs text-foreground-secondary">
            Update metadata only. The current web contract cannot apply this
            release, so viewing it does not change instance files.
          </p>
        </section>
      ) : null}

      {/* Existing instances */}
      <section aria-label="Instances">
        <h3 className="text-sm font-semibold text-foreground">
          {instances.length === 0 ? 'Not installed' : instances.length === 1 ? '1 instance' : `${instances.length} instances`}
        </h3>
        {instances.length > 0 ? (
          <ul className="mt-1 divide-y divide-border rounded-md border border-border">
            {instances.map((instance) => (
              <li key={instance.id}>
                <Link
                  to={`/app/${instance.id}`}
                  className="flex min-h-row items-center gap-2 px-2.5 text-sm text-foreground transition-colors duration-instant hover:bg-hover"
                >
                  <InstanceGlyphTile instance={instance} />
                  <span className="min-w-0 flex-1 truncate">{instance.name}</span>
                  <ArrowUpRight className="size-3.5 text-foreground-tertiary" aria-hidden="true" />
                </Link>
              </li>
            ))}
          </ul>
        ) : null}
      </section>

      {/* Version history (what the catalog provides) */}
      <section aria-label="Version history">
        <h3 className="text-sm font-semibold text-foreground">Version history</h3>
        <ul className="mt-1 flex flex-col gap-1 text-sm">
          {entry.updateAvailable ? (
            <li className="flex items-baseline gap-2">
              <span className="tnum font-mono text-xs text-foreground">v{entry.updateAvailable.toVersion}</span>
              <span className="text-foreground-secondary">available — {entry.updateAvailable.releaseNotes}</span>
            </li>
          ) : null}
          <li className="flex items-baseline gap-2">
            <span className="tnum font-mono text-xs text-foreground">v{pkg.version}</span>
            <span className="text-foreground-secondary">
              {entry.updateAvailable ? 'installed release' : 'current release'} · {releaseStatusLabel(pkg.releaseStatus)}
            </span>
          </li>
        </ul>
      </section>

      {/* Technical details — on demand only (catalog.md: never in rows) */}
      <Disclosure
        title="Details"
        className="rounded-md border border-border bg-surface-2"
        headerExtra={<CopyButton text={rawDescriptor} label="Copy package descriptor" />}
      >
        <dl className="flex flex-col px-3 pt-1">
          <FactRow label="Package ID">
            <span className="tnum font-mono text-xs">{pkg.id}</span>
          </FactRow>
          <FactRow label="Machine name">
            <span className="tnum font-mono text-xs">{pkg.name}</span>
          </FactRow>
          <FactRow label="Workbench tools">
            {pkg.workbenchTools.length > 0 ? pkg.workbenchTools.join(', ') : 'None'}
          </FactRow>
          <FactRow label="Views">{pkg.views.join(', ')}</FactRow>
        </dl>
        <p className="px-3 pt-2 text-xs font-medium text-foreground-secondary">Raw descriptor</p>
        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words px-3 pb-3 pt-1 font-mono text-code text-foreground-secondary">
          {rawDescriptor}
        </pre>
      </Disclosure>
    </div>
  )
}
