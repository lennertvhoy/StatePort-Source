/**
 * InstallReview — the heart of the catalog surface (catalog.md §install flow).
 * Clicking Install opens a review step — never an instant install:
 *   1. What this is (identity, review classification, release status)
 *   2. What it can do (plain-language permission rows)
 *   3. What will be created (editable instance name, storage, views)
 *   4. Whether approval is required
 * Confirm → progress steps → success view with Open instance. Install failure
 * is honest: an inline error, nothing half-installed, Retry.
 */
import {
  CircleCheck,
  FolderLock,
  Globe,
  HardDrive,
  SquareTerminal,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import type { ApplicationInstance, CatalogInstallResult, CatalogPackage } from '@/client'
import { getClient } from '@/client'
import { Disclosure, InlineNotice, StatusBadge } from '@/components'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { applicationDestinationAvailable } from '@/features/application-experience/registry'

import { hasElevatedScope, networkPolicyLabel, releaseStatusLabel, reviewClassificationPresentation } from './catalogModel'

type Phase = 'review' | 'installing' | 'success'

function PermissionRow({ icon: Icon, label, text }: { icon: LucideIcon; label: string; text: string }) {
  return (
    <li className="flex items-start gap-2.5 py-1.5">
      <Icon className="mt-0.5 size-4 shrink-0 text-foreground-secondary" aria-hidden="true" />
      <div className="min-w-0">
        <p className="text-sm font-medium text-foreground">{label}</p>
        <p className="text-sm text-foreground-secondary">{text}</p>
      </div>
    </li>
  )
}

export interface InstallReviewProps {
  entry: CatalogPackage | null
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Called after a successful install so the list can refresh its counts. */
  onInstalled: (instance: ApplicationInstance) => void
}

/**
 * Rendered inside the detail drawer's host (CatalogPage) — the review is a
 * second-layer panel: it replaces the drawer body content while open, keeping
 * focus inside the same dialog tree.
 */
export function InstallReview({ entry, open, onOpenChange, onInstalled }: InstallReviewProps) {
  const navigate = useNavigate()
  const [phase, setPhase] = useState<Phase>('review')
  const [instanceName, setInstanceName] = useState('')
  const [error, setError] = useState<unknown>(null)
  const [result, setResult] = useState<CatalogInstallResult | null>(null)

  // Reset whenever a (new) package review opens (render-time adjustment —
  // no effect setState). The null initializer makes the first open reset too.
  const openedFor = open && entry ? entry.pkg.id : null
  const [prevOpenedFor, setPrevOpenedFor] = useState<string | null>(null)
  if (prevOpenedFor !== openedFor) {
    setPrevOpenedFor(openedFor)
    if (openedFor && entry) {
      setPhase('review')
      setInstanceName(entry.pkg.displayName)
      setError(null)
      setResult(null)
    }
  }

  if (!entry) return null
  const { pkg } = entry
  const classification = reviewClassificationPresentation(pkg)
  const elevated = hasElevatedScope(pkg)
  const trimmedName = instanceName.trim()

  const confirmInstall = async () => {
    setPhase('installing')
    setError(null)
    try {
      const created = await getClient().catalog.createInstance(pkg.id, { name: trimmedName })
      // The mutation response is not enough to claim success. Re-read both
      // durable projections before showing an instance or receipt link.
      const instance = await getClient().applications.get(created.instance.id)
      const receipt = await getClient().receipts.get(created.receipt.id, instance.id)
      const durableDigest = receipt.payloadDigest
      if (
        receipt.id !== created.receipt.id ||
        receipt.instanceId !== instance.id ||
        !durableDigest ||
        durableDigest.value !== created.receipt.digest.value
      ) {
        throw new Error('The durable installation receipt did not match the created application or digest.')
      }
      setResult({ instance, receipt: { id: receipt.id, digest: durableDigest } })
      setPhase('success')
      onInstalled(instance)
    } catch (err) {
      setError(err)
      setPhase('review')
    }
  }

  const openInstance = () => {
    if (!result) return
    onOpenChange(false)
    navigate(`/app/${result.instance.id}`)
  }

  if (phase === 'installing') {
    return (
      <div className="flex flex-col gap-3 py-6" data-testid="install-progress" aria-live="polite" aria-busy="true">
        <p className="text-sm font-medium text-foreground">Installing {pkg.displayName}</p>
        <div role="progressbar" aria-label="Installation progress" className="h-1 overflow-hidden rounded-full bg-active">
          <div className="h-full w-1/3 animate-pulse rounded-full bg-accent" />
        </div>
        <p className="text-sm text-foreground-secondary">
          Waiting for the service to confirm the durable instance and receipt. Progress is indeterminate until that read-back completes.
        </p>
      </div>
    )
  }

  if (phase === 'success' && result) {
    const { instance, receipt } = result
    const canOpenReceipts = applicationDestinationAvailable(instance, 'receipts')
    return (
      <div className="flex flex-col gap-4 py-4" data-testid="install-success">
        <div className="flex items-start gap-2.5">
          <CircleCheck className="mt-0.5 size-5 shrink-0 text-status-success" aria-hidden="true" />
          <div>
            <p className="text-md font-semibold text-foreground">{instance.name} is installed</p>
            <p className="mt-0.5 text-sm text-foreground-secondary">
              The application was created in its own folder on this device. Nothing else was changed.
            </p>
          </div>
        </div>
        <div className="flex flex-col gap-2">
          <Button onClick={openInstance} data-testid="open-instance">
            Open instance
          </Button>
          {canOpenReceipts ? (
            <Button asChild variant="outline">
              <Link
                to={`/app/${instance.id}/receipts/${receipt.id}?digest=${encodeURIComponent(receipt.digest.value)}`}
                data-testid="view-install-receipt"
              >
                View installation receipt
              </Link>
            </Button>
          ) : null}
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Done
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4" data-testid="install-review">
      {/* 1 — What this is */}
      <section aria-label="What this is">
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-md font-semibold text-foreground">{pkg.displayName}</p>
          <StatusBadge state={classification.state} label={classification.label} icon={classification.icon} />
        </div>
        <p className="mt-0.5 text-xs text-foreground-secondary">
          {releaseStatusLabel(pkg.releaseStatus)} · v{pkg.version} · published to the StatePort catalog
        </p>
        <dl className="mt-2 grid grid-cols-1 gap-1 text-xs text-foreground-secondary sm:grid-cols-2" data-testid="package-eligibility">
          <div className="flex gap-1.5">
            <dt>Production eligibility:</dt>
            <dd className="font-medium text-foreground">
              {pkg.productionEligible === true ? 'Eligible by declaration' : pkg.productionEligible === false ? 'Not eligible' : 'Not reported'}
            </dd>
          </div>
          <div className="flex gap-1.5">
            <dt>Public-safe fixture:</dt>
            <dd className="font-medium text-foreground">
              {pkg.publicSafe === true ? 'Yes' : pkg.publicSafe === false ? 'No' : 'Not reported'}
            </dd>
          </div>
        </dl>
      </section>

      {/* 2 — What it can do (plain language first) */}
      <section aria-label="What it can do">
        <h3 className="text-sm font-semibold text-foreground">What it can do</h3>
        <ul className="mt-1 divide-y divide-border">
          <PermissionRow icon={FolderLock} label="Local files" text={pkg.permissions.fileAccess} />
          <PermissionRow icon={SquareTerminal} label="Terminal" text={pkg.permissions.terminalAccess} />
          <PermissionRow icon={Globe} label="Network" text={pkg.permissions.networkAccess} />
          <PermissionRow icon={HardDrive} label="Your data" text={pkg.permissions.dataOwnership} />
        </ul>
        {elevated ? (
          <InlineNotice tone="attention" className="mt-2" title="Elevated scope">
            This package can run terminal commands or reach the network from its project environment. The scope is
            limited to {networkPolicyLabel(pkg.networkPolicy).toLowerCase()} and its own folder.
          </InlineNotice>
        ) : null}
      </section>

      {/* 3 — What will be created */}
      <section aria-label="What will be created" className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold text-foreground">What will be created</h3>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="instance-name">Instance name</Label>
          <Input
            id="instance-name"
            value={instanceName}
            onChange={(e) => setInstanceName(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            data-testid="instance-name-input"
          />
        </div>
        <dl className="flex flex-col gap-1 text-sm">
          <div className="flex gap-2">
            <dt className="w-24 shrink-0 text-foreground-secondary">Storage</dt>
            <dd className="text-foreground">
              {pkg.dataBoundaries[0] ?? 'Its own folder'} — on this device
            </dd>
          </div>
          <div className="flex gap-2">
            <dt className="w-24 shrink-0 text-foreground-secondary">Views added</dt>
            <dd className="text-foreground">
              {pkg.views.length > 0 ? pkg.views.join(', ') : 'Resolved from the application experience after installation'}
            </dd>
          </div>
        </dl>
      </section>

      {/* 4 — Whether approval is required */}
      <section aria-label="Approval">
        <p className="text-sm text-foreground">
          Installing this package requires your confirmation. It does not change any existing application.
        </p>
        {entry.installRequiresApproval ? (
          <p className="mt-1 text-sm text-foreground-secondary">This package also requires approval before first run.</p>
        ) : null}
        {pkg.reviewClassification === 'community' ? (
          <Disclosure title="Why this matters" className="mt-2">
            <p className="px-2 pb-2 text-sm text-foreground-secondary">
              Reviewed packages are checked by the StatePort project before they appear here. Community packages are
              checked only for their declared data boundaries — read the permission summary above before installing.
            </p>
          </Disclosure>
        ) : null}
      </section>

      {error ? (
        <div className="flex flex-col gap-2" data-testid="install-error">
          <InlineNotice
            tone="danger"
            title="Installation result could not be confirmed"
          >
            {error instanceof Error ? error.message : 'The installation request could not be confirmed.'}{' '}
            Do not retry this mutation from the same review. Close it and
            refresh the Catalog to inspect whether the instance was created.
          </InlineNotice>
          <Disclosure title="Technical details">
            <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words px-2 pb-2 font-mono text-xs text-foreground-secondary">
              {error instanceof Error ? (error.stack ?? error.message) : String(error)}
            </pre>
          </Disclosure>
        </div>
      ) : null}

      {/* Footer actions (sticky within the drawer body) */}
      <div className="sticky bottom-0 -mx-1 mt-1 flex items-center justify-end gap-2 border-t border-border bg-surface px-1 pt-3 pb-1">
        <Button variant="ghost" onClick={() => onOpenChange(false)}>
          Cancel
        </Button>
        <Button
          disabled={trimmedName === '' || Boolean(error)}
          onClick={() => void confirmInstall()}
          data-testid="confirm-install"
        >
          Install “{trimmedName || pkg.displayName}”
        </Button>
      </div>
    </div>
  )
}
