/**
 * Canonical application-source HTTP client.
 *
 * Public reads use the bounded registry projection. Exact source evidence and
 * development verification use independently permission-gated operator
 * endpoints; the client binds every response back to the requested identity.
 */
import type { SourcesClient } from '../client'
import { ClientError } from '../types'

import { endpoints } from './endpoints'
import {
  canonicalSourceIndexSchema,
  canonicalSourceOperatorViewSchema,
  developmentSourceResolutionSchema,
  developmentSourceVerificationInputSchema,
} from './sourceSchemas'
import { HttpTransport } from './transport'

function identityMismatch(detail: string): never {
  throw new ClientError('validation', 'The source response did not match the requested identity', {
    detail,
  })
}

export class HttpSourcesClient implements SourcesClient {
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async list() {
    const result = await this.transport.request(endpoints.sources, {
      schema: canonicalSourceIndexSchema,
    })
    return result.sources
  }

  async getOperatorDetail(sourceId: string) {
    const result = await this.transport.request(endpoints.source(sourceId), {
      schema: canonicalSourceOperatorViewSchema,
    })
    if (result.sourceId !== sourceId) {
      identityMismatch(`requested ${sourceId}; received ${result.sourceId}`)
    }
    return result
  }

  async verifyDevelopmentCandidate(input: Parameters<SourcesClient['verifyDevelopmentCandidate']>[0]) {
    const exact = developmentSourceVerificationInputSchema.safeParse(input)
    if (!exact.success) {
      throw new ClientError('validation', 'Development source verification requires an exact candidate identity', {
        detail: exact.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join('\n'),
      })
    }
    const result = await this.transport.request(endpoints.sourceDevelopmentResolve(exact.data.sourceId), {
      method: 'POST',
      mutation: true,
      body: exact.data,
      schema: developmentSourceResolutionSchema,
    })
    if (
      result.sourceId !== exact.data.sourceId ||
      result.sourceClass !== exact.data.sourceClass ||
      result.identity.commit !== exact.data.expectedCommit ||
      result.identity.tree !== exact.data.expectedTree ||
      result.identity.manifestDigest !== exact.data.expectedManifestDigest ||
      result.identity.sourceDigest !== exact.data.expectedSourceDigest
    ) {
      identityMismatch('the verification receipt was for a different candidate identity')
    }
    return result
  }
}
