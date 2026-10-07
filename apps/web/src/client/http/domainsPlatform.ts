/**
 * Operator-only platform evidence clients.
 *
 * Role-aware presentation is a request-suppression boundary, not authority:
 * this client refuses locally without the exact status permission bits and
 * the service independently authorizes every request.
 */
import { z } from 'zod'

import type { PlatformStateBenchClient } from '../client'
import { canInspectPlatformStateBench, ClientError } from '../types'
import { endpoints } from './endpoints'
import { mapPlatformStateBench } from './mappers'
import { HttpTransport } from './transport'

const unknownPayload = z.unknown()

export class HttpPlatformStateBenchClient implements PlatformStateBenchClient {
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async getMatrix(status: Parameters<PlatformStateBenchClient['getMatrix']>[0]) {
    if (!canInspectPlatformStateBench(status)) {
      throw new ClientError('unavailable', 'Platform StateBench evidence requires operator access', {
        detail: 'The operator-only endpoint was not requested.',
      })
    }
    const payload = await this.transport.request(endpoints.platformStateBench, {
      schema: unknownPayload,
    })
    return mapPlatformStateBench(payload)
  }
}
