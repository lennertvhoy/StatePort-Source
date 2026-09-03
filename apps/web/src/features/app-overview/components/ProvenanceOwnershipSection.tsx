/**
 * Application-scoped provenance and file ownership.
 *
 * This renders only the bounded `PersistentApp.inspect()` projection already
 * normalized by the HTTP adapter. Human-facing trust/ownership facts remain
 * visible; exact immutable identities and relative paths require deliberate
 * progressive disclosure.
 */
import type {
  ApplicationOwnershipCategory,
  ApplicationProvenance,
  ApplicationSourceIdentity,
  SemanticState,
} from '@/client'
import { Disclosure, SectionHeader, StatusBadge } from '@/components'

const OWNERSHIP_LABELS: Record<ApplicationOwnershipCategory, string> = {
  template: 'Template',
  instance: 'Instance',
  generated: 'Generated',
  override: 'Override',
}

const OWNERSHIP_CATEGORIES = [
  'template',
  'instance',
  'generated',
  'override',
] as const satisfies readonly ApplicationOwnershipCategory[]

interface SourcePresentation {
  label: string
  state: SemanticState
  detail: string
}

function sourcePresentation(source: ApplicationSourceIdentity): SourcePresentation {
  if (
    source.ownership === 'user_owned_repository' ||
    source.sourceKind === 'local'
  ) {
    return {
      label: 'User-owned repository',
      state: 'informational',
      detail: 'Registered in place. StatePort projects evidence without taking ownership of the repository.',
    }
  }

  if (source.sourceAccessClass === 'development_candidate') {
    return {
      label: 'Development candidate - local testing only',
      state: 'waiting',
      detail: 'Production installation remains blocked by the effective source-access grant.',
    }
  }
  if (source.sourceAccessClass === 'canonical_release') {
    return {
      label: 'Canonical release source',
      state: 'success',
      detail: 'Effective source access permits production installation.',
    }
  }

  switch (source.sourceClass) {
    case 'canonical_release':
      return {
        label: 'Canonical release claim - access not recorded',
        state: 'attention',
        detail: 'The source declares a canonical release, but no effective source-access grant is recorded.',
      }
    case 'canonical_source':
      return {
        label: 'Canonical source - access not recorded',
        state: 'attention',
        detail:
          source.productionEligible === false
            ? 'The source declares canonical identity without production eligibility or an effective access grant.'
            : 'The source declares canonical identity, but no effective source-access grant is recorded.',
      }
    case 'development_candidate':
      return {
        label: 'Development candidate',
        state: 'waiting',
        detail: 'Candidate evidence is not a canonical release or production acceptance.',
      }
    case 'synthetic_fixture':
      return {
        label: 'Synthetic fixture',
        state: 'informational',
        detail: 'This is invented test content, not a canonical production source.',
      }
    case 'compatibility_fixture':
    case 'compatibility_snapshot':
      return {
        label: 'Compatibility source',
        state: 'neutral',
        detail: 'This source exists for compatibility and does not establish canonical release authority.',
      }
    case 'legacy_local_development':
      return {
        label: 'Legacy development source',
        state: 'attention',
        detail: 'A compatibility-era local source is recorded; it is not production authority.',
      }
    default:
      if (source.sourceKind === 'bundled_public_fixture') {
        return {
          label: 'Bundled public fixture',
          state: 'informational',
          detail: 'This reviewed fixture supports local product validation, not a canonical source claim.',
        }
      }
      return {
        label: 'Recorded source',
        state: 'neutral',
        detail: 'StatePort has bounded source evidence. No stronger release or acceptance claim is inferred.',
      }
  }
}

function IdentityFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[7.5rem_minmax(0,1fr)] items-start gap-2 py-1">
      <dt className="text-xs font-medium text-foreground-secondary">{label}</dt>
      <dd className="min-w-0 break-all font-mono text-xs text-foreground">{value}</dd>
    </div>
  )
}

function ExactSourceIdentity({ source }: { source: ApplicationSourceIdentity }) {
  const facts = [
    source.templateId ? ['Template ID', source.templateId] : null,
    source.version ? ['Version', source.version] : null,
    source.repository ? ['Repository', source.repository] : null,
    source.resolvedCommit ? ['Git commit', source.resolvedCommit] : null,
    source.resolvedTree ? ['Git tree', source.resolvedTree] : null,
    source.manifestDigest ? ['Manifest digest', source.manifestDigest] : null,
    source.sourceDigest ? ['Source digest', source.sourceDigest] : null,
    source.compatibilityRevision
      ? ['Compatibility revision', source.compatibilityRevision]
      : null,
    source.compatibilityTree ? ['Compatibility tree', source.compatibilityTree] : null,
    source.sourceClass ? ['Source class ID', source.sourceClass] : null,
    source.sourceKind ? ['Source kind ID', source.sourceKind] : null,
    source.ownership ? ['Ownership ID', source.ownership] : null,
    source.productionEligible !== undefined
      ? ['Production eligible', source.productionEligible ? 'true' : 'false']
      : null,
    source.sourceAccessClass ? ['Effective access', source.sourceAccessClass] : null,
    source.productionInstallAllowed !== undefined
      ? ['Production install', source.productionInstallAllowed ? 'allowed' : 'blocked']
      : null,
  ].filter((fact): fact is [string, string] => fact !== null)

  return (
    <section aria-labelledby="provenance-exact-heading">
      <h3 id="provenance-exact-heading" className="text-sm font-semibold text-foreground">
        Exact source identity
      </h3>
      {source.compatibilityRevision ? (
        <p className="mt-1 text-xs text-foreground-secondary">
          Compatibility references are raw legacy identities, not verified Git object IDs.
        </p>
      ) : null}
      {facts.length > 0 ? (
        <dl className="mt-1">{facts.map(([label, value]) => <IdentityFact key={label} label={label} value={value} />)}</dl>
      ) : (
        <p className="mt-1 text-sm text-foreground-secondary">
          No browser-safe immutable source identity is recorded.
        </p>
      )}
    </section>
  )
}

function OwnershipPaths({ provenance }: { provenance: ApplicationProvenance }) {
  const ownership = provenance.ownership
  if (!ownership) {
    return (
      <section aria-labelledby="provenance-paths-heading">
        <h3 id="provenance-paths-heading" className="text-sm font-semibold text-foreground">
          File ownership
        </h3>
        <p className="mt-1 text-sm text-foreground-secondary">
          No bounded ownership projection is available.
        </p>
      </section>
    )
  }

  return (
    <section aria-labelledby="provenance-paths-heading">
      <h3 id="provenance-paths-heading" className="text-sm font-semibold text-foreground">
        Bounded ownership paths
      </h3>
      <div className="mt-2 grid gap-3 sm:grid-cols-2">
        {OWNERSHIP_CATEGORIES.map((category) => {
          const paths = ownership.paths[category]
          const count = ownership.counts[category]
          return (
            <div
              key={category}
              className="min-w-0 rounded-sm border border-border bg-surface-subtle px-2.5 py-2"
              data-testid={`ownership-paths-${category}`}
            >
              <h4 className="text-xs font-semibold text-foreground">
                {OWNERSHIP_LABELS[category]} ({count})
              </h4>
              {paths.length > 0 ? (
                <ul className="mt-1 space-y-0.5">
                  {paths.map((path) => (
                    <li key={path} className="truncate font-mono text-xs text-foreground-secondary" title={path}>
                      {path}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-1 text-xs text-foreground-tertiary">No paths recorded.</p>
              )}
              {ownership.truncated[category] ? (
                <p className="mt-1 text-xs text-foreground-tertiary">
                  Showing {paths.length} of {count}; the projection is bounded.
                </p>
              ) : null}
            </div>
          )
        })}
      </div>
    </section>
  )
}

export function ProvenanceOwnershipSection({
  provenance,
}: {
  provenance: ApplicationProvenance
}) {
  const presentation = sourcePresentation(provenance.source)
  const ownership = provenance.ownership

  return (
    <section aria-label="Provenance and ownership" data-testid="provenance-ownership-section">
      <SectionHeader title="Provenance & ownership" className="mb-2" />
      <div className="rounded-md border border-border bg-surface px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge state={presentation.state} label={presentation.label} />
          {provenance.source.version ? (
            <span className="text-xs text-foreground-secondary">
              Version {provenance.source.version}
            </span>
          ) : null}
        </div>
        <p className="mt-1.5 text-xs text-foreground-secondary">{presentation.detail}</p>

        {ownership ? (
          <dl className="mt-2 flex flex-wrap gap-x-4 gap-y-1" aria-label="File ownership counts">
            {OWNERSHIP_CATEGORIES.map((category) => (
              <div key={category} className="flex items-baseline gap-1">
                <dt className="text-xs text-foreground-secondary">{OWNERSHIP_LABELS[category]}</dt>
                <dd
                  className="tnum text-xs font-semibold text-foreground"
                  data-testid={`ownership-count-${category}`}
                >
                  {ownership.counts[category]}
                </dd>
              </div>
            ))}
          </dl>
        ) : null}

        <Disclosure title="Exact identity and bounded paths" defaultOpen={false} className="mt-2 border-t border-border pt-1">
          <div className="grid gap-4 px-2 pb-2 pt-1" data-testid="provenance-exact-detail">
            <ExactSourceIdentity source={provenance.source} />
            <OwnershipPaths provenance={provenance} />
          </div>
        </Disclosure>
      </div>
    </section>
  )
}
