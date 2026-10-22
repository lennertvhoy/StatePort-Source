/**
 * Client boundary entry point.
 *
 * `getClient()` returns the singleton `StatePortClient`, selected by
 * environment (binding doc §12):
 *
 *   - `VITE_STATEPORT_ADAPTER=mock|http` wins explicitly when set;
 *   - otherwise development builds default to `mock`, production builds to
 *     `http`.
 *
 * The two adapters never mix: in `http` mode the mock adapter is never
 * constructed, and a failed production request surfaces an honest
 * ClientError instead of silently switching to fake data.
 *
 * The mock adapter and Scenario Lab are development/demo/test code. This
 * module does not import them: `src/dev/installMock.ts` registers the mock
 * through `registerMockClient`, and `main.tsx` loads that file with a dynamic
 * import behind the build-time adapter flag, so a production build contains
 * none of it (checked by `npm run check:bundle`).
 *
 * Components and stores import from `@/client` only — never from adapter
 * internals.
 */
import type { StatePortClient } from './client'
import { HttpClient } from './http/adapter'

export * from './types'
export type {
  StatePortClient,
  SessionClient,
  ApplicationsClient,
  CatalogClient,
  SourcesClient,
  PlatformStateBenchClient,
  GlobalSettingsClient,
  AppSettingsClient,
  ActivityClient,
  ApprovalsClient,
  ConversationClient,
  ReceiptsClient,
  FilesClient,
  FileWorkbenchAdapter,
  TerminalClient,
  InfrastructureClient,
  OrchestrationClient,
  RecoveryClient,
  OperationsClient,
  ScenarioClient,
  RunsClient,
  ContextClient,
  ExecutionHostClient,
  WorkspaceAuthorityProjection,
  WorkspaceAuthorityRequest,
  WorkspaceAuthorityPreparation,
  ExecutionHostStatus,
  ExecutionHostResult,
  ExecutionHostOperationReceipt,
  ExecutionHostReceiptIndex,
  RepositoryImportClient,
  PlatformDeploymentsClient,
  AuthorityClient,
  UpdaterClient,
  PreviewRoutesClient,
  ConversationSendInput,
  SettingsRollbackInput,
  DeepPartial,
} from './client'
export type { ScenarioId } from './mock/scenarios'
export { HttpTransport } from './http/adapter'
export { schemas } from './schemas'

let singleton: StatePortClient | null = null
let mockFactory: (() => StatePortClient) | null = null

/** Development, demo and test seam: supply the mock adapter (see src/dev/installMock.ts). */
export function registerMockClient(factory: (() => StatePortClient) | null): void {
  mockFactory = factory
  singleton = null
}

export function getClient(): StatePortClient {
  if (singleton) return singleton
  const explicit = import.meta.env.VITE_STATEPORT_ADAPTER
  const adapter: 'mock' | 'http' =
    explicit === 'http' || explicit === 'mock' ? explicit : import.meta.env.DEV ? 'mock' : 'http'
  if (adapter === 'mock') {
    if (!mockFactory) throw new Error('The mock adapter was selected but is not loaded in this build.')
    singleton = mockFactory()
  } else {
    singleton = new HttpClient()
  }
  return singleton
}

/** Test seam: drop the singleton so a fresh adapter is constructed. */
export function resetClientForTests(): void {
  singleton = null
}
