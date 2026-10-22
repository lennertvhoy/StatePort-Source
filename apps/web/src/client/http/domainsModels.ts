/**
 * HTTP domain client — model routes (keep-up loop level 1).
 *
 * Mutations return nothing to the caller on purpose: the page re-reads
 * `GET /v1/models` after every change, so what it shows is always the
 * service's recorded state and never an optimistic local guess.
 */
import { z } from 'zod'

import { MAX_MODELS_PER_EVALUATION, type ModelsClient } from '../models'
import { ClientError } from '../types'
import { endpoints } from './endpoints'
import { mapEvaluateResponse, mapModelsView, mapSuiteRun } from './modelsWire'
import type { HttpTransport } from './transport'

const unknownPayload = z.unknown()

export class HttpModelsClient implements ModelsClient {
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async getView() {
    const payload = await this.transport.request(endpoints.models, { schema: unknownPayload })
    return mapModelsView(payload)
  }

  async grantConsent(input: { destination: string; termsSha256: string }) {
    await this.transport.request(endpoints.modelsConsent, {
      method: 'POST',
      body: { destination: input.destination, termsSha256: input.termsSha256 },
      schema: unknownPayload,
    })
  }

  async withdrawConsent(destination: string) {
    await this.transport.request(endpoints.modelsConsent, {
      method: 'DELETE',
      body: { destination },
      schema: unknownPayload,
    })
  }

  async observe() {
    await this.transport.request(endpoints.modelsObserve, { method: 'POST', body: {}, schema: unknownPayload })
  }

  async evaluate(models: string[]) {
    const unique = [...new Set(models)]
    if (unique.length === 0 || unique.length > MAX_MODELS_PER_EVALUATION) {
      throw new ClientError('validation', `Choose between 1 and ${MAX_MODELS_PER_EVALUATION} models to evaluate.`)
    }
    const payload = await this.transport.request(endpoints.modelsEvaluate, {
      method: 'POST',
      body: { models: unique },
      schema: unknownPayload,
    })
    return mapEvaluateResponse(payload)
  }

  async getRun(runId: string) {
    const payload = await this.transport.request(endpoints.modelsRun(runId), { schema: unknownPayload })
    return mapSuiteRun(payload, runId)
  }

  async setRoute(input: { actionClass: string; model: string | null; pin: boolean }) {
    await this.transport.request(endpoints.modelsRoute, {
      method: 'POST',
      body: { actionClass: input.actionClass, model: input.model, pin: input.pin },
      schema: unknownPayload,
    })
  }

  async setLease(input: { enabled: boolean; days: number }) {
    await this.transport.request(endpoints.modelsLease, {
      method: 'POST',
      body: { enabled: input.enabled, days: input.days },
      schema: unknownPayload,
    })
  }

  async decideProposal(proposalId: string, decision: 'switch' | 'dismiss') {
    await this.transport.request(endpoints.modelsProposal(proposalId), {
      method: 'POST',
      body: { decision },
      schema: unknownPayload,
    })
  }
}
