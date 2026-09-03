/**
 * HttpClient — the REAL production adapter for the same-origin StatePort
 * service (binding doc §12–§16).
 *
 * - Every domain client talks to the backend contract through HttpTransport.
 * - Failures surface as honest ClientErrors; production never falls back to
 *   mock data.
 * - Endpoint paths are centralized in endpoints.ts.
 */
import type { StatePortClient } from '../client'

import { HttpTransport } from './transport'
import type { HttpTransportOptions } from './transport'
import {
  HttpActivityClient,
  HttpApplicationsClient,
  HttpAppSettingsClient,
  HttpCatalogClient,
  HttpFilesClient,
  HttpGlobalSettingsClient,
  HttpOperationsClient,
  HttpReceiptsClient,
  HttpRecoveryClient,
  HttpRepositoryImportClient,
  HttpScenarioClient,
  HttpSessionClient,
} from './domainsCore'
import { HttpCancellableAssistantConversationClient } from './domainsCancellableAssistantConversation'
import { HttpPlatformStateBenchClient } from './domainsPlatform'
import {
  DigestApproval,
  HttpAuthorityClient,
  HttpPlatformDeploymentsClient,
  HttpPreviewRoutesClient,
  HttpUpdaterClient,
} from './domainsPlatformSurface'
import { HttpSourcesClient } from './domainsSources'
import {
  HttpApprovalsClient,
  HttpContextClient,
  HttpInfrastructureClient,
  HttpOrchestrationClient,
  HttpRunsClient,
} from './domainsExecution'
import { HttpTerminalClient } from './terminal'
import type { HttpTerminalClientOptions } from './terminal'
import { HttpExecutionHostClient } from './domainsExecutionHost'

export { HttpTransport }
export type { HttpTransportOptions }
export { endpoints, FORMAT, TERMINAL_SUBPROTOCOL, TERMINAL_TICKET_FORMAT } from './endpoints'
export { TerminalSocket } from './terminalSocket'
export type { TerminalTicket } from './mappers'

export interface HttpClientOptions extends HttpTransportOptions {
  terminal?: HttpTerminalClientOptions
}

export class HttpClient implements StatePortClient {
  readonly adapter = 'http' as const
  readonly transport: HttpTransport

  readonly session: StatePortClient['session']
  readonly applications: StatePortClient['applications']
  readonly catalog: StatePortClient['catalog']
  readonly sources: StatePortClient['sources']
  readonly platformStateBench: StatePortClient['platformStateBench']
  readonly globalSettings: StatePortClient['globalSettings']
  readonly appSettings: StatePortClient['appSettings']
  readonly activity: StatePortClient['activity']
  readonly approvals: StatePortClient['approvals']
  readonly conversation: StatePortClient['conversation']
  readonly receipts: StatePortClient['receipts']
  readonly files: StatePortClient['files']
  readonly terminal: StatePortClient['terminal']
  readonly infrastructure: StatePortClient['infrastructure']
  readonly orchestration: StatePortClient['orchestration']
  readonly recovery: StatePortClient['recovery']
  readonly operations: StatePortClient['operations']
  readonly scenario: StatePortClient['scenario']
  readonly runs: StatePortClient['runs']
  readonly executionHost: StatePortClient['executionHost']
  readonly context: StatePortClient['context']
  readonly repositoryImport: StatePortClient['repositoryImport']
  readonly platformDeployments: StatePortClient['platformDeployments']
  readonly authority: StatePortClient['authority']
  readonly updater: StatePortClient['updater']
  readonly previewRoutes: StatePortClient['previewRoutes']

  constructor(options: HttpClientOptions = {}) {
    this.transport = new HttpTransport(options)
    const runs = new HttpRunsClient(this.transport)
    const applications = new HttpApplicationsClient(this.transport)
    const infrastructure = new HttpInfrastructureClient(this.transport)
    const digestApproval = new DigestApproval(this.transport)

    this.session = new HttpSessionClient(this.transport)
    this.applications = applications
    this.catalog = new HttpCatalogClient(this.transport)
    this.sources = new HttpSourcesClient(this.transport)
    this.platformStateBench = new HttpPlatformStateBenchClient(this.transport)
    this.globalSettings = new HttpGlobalSettingsClient(this.transport)
    this.appSettings = new HttpAppSettingsClient(this.transport)
    this.activity = new HttpActivityClient(this.transport)
    this.approvals = new HttpApprovalsClient(this.transport, runs, infrastructure)
    // Production conversation authority: durable event journal, refresh
    // reattachment, and per-work disconnect cancellation. The legacy
    // HttpConversationClient remains a compatibility/storage client only.
    this.conversation = new HttpCancellableAssistantConversationClient(
      this.transport,
    )
    this.receipts = new HttpReceiptsClient(this.transport)
    this.files = new HttpFilesClient(this.transport)
    this.terminal = new HttpTerminalClient(this.transport, options.terminal ?? {})
    this.infrastructure = infrastructure
    this.orchestration = new HttpOrchestrationClient(this.transport)
    this.recovery = new HttpRecoveryClient(this.transport, applications)
    this.operations = new HttpOperationsClient(this.transport, runs, infrastructure)
    this.scenario = new HttpScenarioClient()
    this.runs = runs
    this.executionHost = new HttpExecutionHostClient(this.transport)
    this.context = new HttpContextClient(this.transport)
    this.repositoryImport = new HttpRepositoryImportClient(this.transport)
    this.platformDeployments = new HttpPlatformDeploymentsClient(this.transport, digestApproval)
    this.authority = new HttpAuthorityClient(this.transport, digestApproval)
    this.updater = new HttpUpdaterClient(this.transport, digestApproval)
    this.previewRoutes = new HttpPreviewRoutesClient(this.transport)
  }
}
