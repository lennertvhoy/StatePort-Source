import { Link } from 'react-router-dom'

import type { ApplicationInstance } from '@/client'
import { InlineNotice } from '@/components'
import { Button } from '@/components/ui/button'
import { applicationDestinationAvailable } from '@/features/application-experience/registry'

/** Uses the imported source binding and resolved routes, never the template name. */
export function ImportedTemplateJourney({ instance }: { instance: ApplicationInstance }) {
  if (instance.provenance?.source.management !== 'isolated_template') return null
  const canRun = applicationDestinationAvailable(instance, 'runs')
  const canReadReceipts = applicationDestinationAvailable(instance, 'receipts')
  return (
    <section aria-label="First task with this template" className="rounded-md border border-border p-4">
      <h2 className="text-sm font-medium">Inspect your imported state</h2>
      <p className="mt-2 text-sm text-foreground-secondary">
        Start with the template’s reviewed inspection action. It reports the state in this isolated copy and
        saves a durable result. This first inspection does not change your template or require a provider login.
      </p>
      <ol className="my-3 list-decimal space-y-1 pl-5 text-sm text-foreground-secondary">
        <li>Open Runs and select the declared inspection action.</li>
        <li>Prepare it, review the exact action and authority, then approve and execute.</li>
        <li>Read the result and its evidence. Runs and receipts remain available after restart.</li>
      </ol>
      {!canRun ? (
        <InlineNotice tone="attention">Runs are unavailable for this instance. Review its capabilities before continuing.</InlineNotice>
      ) : null}
      <div className="flex flex-wrap gap-2">
        {canRun ? <Button asChild><Link to={`/app/${instance.id}/runs`}>Review first inspection</Link></Button> : null}
        {canReadReceipts ? <Button asChild variant="outline"><Link to={`/app/${instance.id}/receipts`}>Inspect durable receipts</Link></Button> : null}
      </div>
    </section>
  )
}
