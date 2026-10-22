/// <reference types="node" />
import { createHash } from 'node:crypto'
import { vi } from 'vitest'

import type { ModelsClient, ModelsView, ModelSuiteRun } from '@/client/models'
import { mapModelsView } from '@/client/http/modelsWire'

export const TERMS = 'During the free period, data sent to this model may be used to improve it.'
export const TERMS_SHA = `sha256:${createHash('sha256').update(TERMS, 'utf8').digest('hex')}`
export const FREE = 'opencode/deepseek-v4.1-flash-free'
export const OTHER_FREE = 'opencode/beam-free'
export const ACCOUNT_MODEL = 'anthropic/claude-x'

/**
 * A wire projection in the documented shape
 * (`stateport.models-projection/v1`). Fixtures are built here and mapped
 * through the real mapper, so a test never asserts on an invented shape.
 */
export function modelsProjection(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    formatVersion: 'stateport.models-projection/v1',
    status: {
      state: 'not_consented',
      detail: 'Free models are off until you accept the OpenCode Zen terms.',
      harness: { id: 'opencode', present: true, version: '1.18.31' },
    },
    consent: {
      destination: 'opencode-free',
      state: 'not_granted',
      grantedAt: null,
      grantedBy: null,
      grantedTermsSha256: null,
      terms: { provider: 'OpenCode Zen', url: 'https://opencode.ai/docs/zen', text: TERMS, sha256: TERMS_SHA },
    },
    catalogue: {
      observedAt: '2026-10-21T08:00:00Z',
      observations: 3,
      harness: { id: 'opencode', version: '1.18.31' },
      lastError: null,
      availabilityWindowSeconds: 604800,
      cache: null,
      models: [
        {
          id: FREE,
          free: true,
          destination: 'opencode-free',
          listedNow: true,
          usable: true,
          firstSeenAt: '2026-10-20T08:00:00Z',
          lastSeenAt: '2026-10-21T08:00:00Z',
          seenCount: 3,
          lastProbe: null,
          latestResult: {
            runId: 'run-1', finishedAt: '2026-10-21T09:00:00Z', state: 'completed',
            available: true, complete: true, passed: 2, total: 4, medianSeconds: 63,
            suiteDigest: 'sha256:suite', current: true,
          },
        },
        {
          id: OTHER_FREE,
          free: true,
          destination: 'opencode-free',
          listedNow: true,
          usable: true,
          firstSeenAt: '2026-10-21T08:00:00Z',
          lastSeenAt: '2026-10-21T08:00:00Z',
          seenCount: 1,
          lastProbe: null,
          latestResult: null,
        },
      ],
    },
    alarms: [],
    routes: [
      { actionClass: 'agent.edit-state', model: null, pinned: false, setBy: null, setAt: null, why: 'safe default', ageSeconds: null, score: null, usable: null, refusal: { code: 'route_not_configured', message: 'No model is chosen for agent actions yet.' } },
      { actionClass: 'chat', model: null, pinned: false, setBy: null, setAt: null, why: 'safe default', ageSeconds: null, score: null, usable: null, refusal: { code: 'route_not_configured', message: 'No model is chosen for chat yet.' } },
    ],
    lease: {
      enabled: false, state: 'off', grantedAt: null, expiresAt: null,
      maxSuiteRunsPerDay: 1, runsToday: 0, maxDays: 30, defaultDays: 30,
    },
    suite: {
      valid: true, id: 'model-suite', version: 'v1', digest: 'sha256:suite',
      taskCount: 4, taskTimeoutSeconds: 180,
      tasks: [{ id: 'plain-typo', title: 'Fix a typo', critical: true }],
    },
    evaluation: { activeRunId: null, maxModels: 3, lastRunId: null },
    proposal: null,
    proposals: [],
    schedule: { running: false, intervalSeconds: 86400, nextTickAt: null },
    receipts: [],
    scoresNote: "Scores come from StatePort's practice tasks, not from your work.",
    ...overrides,
  }
}

/** The domain view of a wire projection (through the real mapper). */
export function modelsView(overrides: Record<string, unknown> = {}): ModelsView {
  return mapModelsView(modelsProjection(overrides))
}

/** A projection whose consent is granted and whose agent route points at FREE. */
export function consentedProjection(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return modelsProjection({
    status: {
      state: 'ready',
      detail: 'A consented free-model route and the pinned OpenCode executable are present.',
      harness: { id: 'opencode', present: true, version: '1.18.31' },
      readyClasses: ['agent.edit-state'],
    },
    consent: {
      destination: 'opencode-free',
      state: 'granted',
      grantedAt: '2026-10-21T08:30:00Z',
      grantedBy: 'owner',
      grantedTermsSha256: TERMS_SHA,
      terms: { provider: 'OpenCode Zen', url: 'https://opencode.ai/docs/zen', text: TERMS, sha256: TERMS_SHA },
    },
    routes: [
      {
        actionClass: 'agent.edit-state', model: FREE, pinned: false, setBy: 'owner',
        setAt: '2026-10-21T08:30:00Z', why: 'owner choice', ageSeconds: 600,
        score: { passed: 2, total: 4, medianSeconds: 63, runId: 'run-1', finishedAt: '2026-10-21T09:00:00Z', timeouts: 0 },
        usable: true, refusal: null,
      },
      { actionClass: 'chat', model: null, pinned: false, setBy: null, setAt: null, why: 'safe default', ageSeconds: null, score: null, usable: null, refusal: { code: 'route_not_configured', message: 'No model is chosen for chat yet.' } },
    ],
    ...overrides,
  })
}

/** A projection whose agent route points at FREE but whose consent was never given. */
export function routedWithoutConsent(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return modelsProjection({
    routes: [
      {
        actionClass: 'agent.edit-state', model: FREE, pinned: false, setBy: 'owner',
        setAt: '2026-10-21T08:30:00Z', why: 'owner choice', ageSeconds: 600,
        score: { passed: 2, total: 4, medianSeconds: 63, runId: 'run-1', finishedAt: '2026-10-21T09:00:00Z', timeouts: 0 },
        usable: true, refusal: null,
      },
      { actionClass: 'chat', model: null, pinned: false, setBy: null, setAt: null, why: 'safe default', ageSeconds: null, score: null, usable: null, refusal: { code: 'route_not_configured', message: 'No model is chosen for chat yet.' } },
    ],
    ...overrides,
  })
}

export function suiteRun(overrides: Partial<ModelSuiteRun> = {}): ModelSuiteRun {
  return {
    runId: 'run-1',
    state: 'completed',
    trigger: 'owner',
    by: 'owner',
    createdAt: '2026-10-21T09:00:00Z',
    startedAt: '2026-10-21T09:00:01Z',
    finishedAt: '2026-10-21T09:01:00Z',
    error: null,
    requestedModels: [FREE],
    progress: { completedTasks: 4, totalTasks: 4, currentModel: null, currentTask: null },
    models: [
      {
        model: FREE,
        available: true,
        complete: true,
        isRetry: false,
        probeCause: null,
        timeouts: 0,
        totals: { passed: 2, total: 4, medianSeconds: 63, runId: 'run-1', finishedAt: '2026-10-21T09:01:00Z', timeouts: 0 },
        tasks: [],
      },
    ],
    ...overrides,
  }
}

export function fakeModelsClient(view: ModelsView | (() => Promise<ModelsView>)) {
  const client = {
    getView: vi.fn<ModelsClient['getView']>(typeof view === 'function' ? view : () => Promise.resolve(view)),
    grantConsent: vi.fn<ModelsClient['grantConsent']>(() => Promise.resolve()),
    withdrawConsent: vi.fn<ModelsClient['withdrawConsent']>(() => Promise.resolve()),
    observe: vi.fn<ModelsClient['observe']>(() => Promise.resolve()),
    evaluate: vi.fn<ModelsClient['evaluate']>(() => Promise.resolve({ runId: 'run-1' })),
    getRun: vi.fn<ModelsClient['getRun']>((runId) => Promise.resolve<ModelSuiteRun>(suiteRun({ runId }))),
    setRoute: vi.fn<ModelsClient['setRoute']>(() => Promise.resolve()),
    setLease: vi.fn<ModelsClient['setLease']>(() => Promise.resolve()),
    decideProposal: vi.fn<ModelsClient['decideProposal']>(() => Promise.resolve()),
  }
  return client satisfies ModelsClient
}
