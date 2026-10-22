/**
 * Model-routes client accessor. Like `providerClient`, this is an
 * operator-level HTTP surface that has no mock counterpart: in a build without
 * the service the page shows the honest load error instead of demo data.
 */
import { HttpModelsClient } from './http/domainsModels'
import { HttpTransport } from './http/transport'
import type { ModelsClient } from './models'

export type { ModelsClient } from './models'
export * from './models'

let singleton: ModelsClient | null = null

export function getModelsClient(): ModelsClient {
  if (!singleton) singleton = new HttpModelsClient(new HttpTransport())
  return singleton
}

/** Test seam: inject a fake (or `null` to drop it). */
export function setModelsClientForTests(client: ModelsClient | null): void {
  singleton = client
}
