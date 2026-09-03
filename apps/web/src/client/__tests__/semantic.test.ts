import { describe, expect, it } from 'vitest'

import {
  capabilityPresentation,
  healthStatePresentation,
  instanceHealthPresentation,
  operationStatePresentation,
  receiptResultPresentation,
  receiptValidationPresentation,
  sshStatePresentation,
  vmStatePresentation,
} from '@/semantic'
import type { OperationState, SemanticState } from '../types'

const ALL_OPERATION_STATES: OperationState[] = [
  'draft',
  'proposed',
  'preparing',
  'prepared',
  'awaiting_approval',
  'approved',
  'queued',
  'running',
  'completed',
  'cancelling',
  'paused',
  'interrupted',
  'applied',
  'validating',
  'validated',
  'completed_without_change',
  'rejected',
  'cancelled',
  'blocked',
  'unavailable',
  'failed',
  'human_accepted',
]

describe('semantic status layer', () => {
  it('maps all honest operation states per design.md §7.1', () => {
    expect(ALL_OPERATION_STATES).toHaveLength(22)
    const expected: Record<string, [SemanticState, string]> = {
      draft: ['neutral', 'Draft'],
      proposed: ['informational', 'Proposed'],
      preparing: ['waiting', 'Preparing'],
      prepared: ['informational', 'Prepared'],
      awaiting_approval: ['waiting', 'Awaiting approval'],
      approved: ['success', 'Approved'],
      queued: ['waiting', 'Queued'],
      running: ['waiting', 'Running'],
      completed: ['informational', 'Completed'],
      cancelling: ['waiting', 'Cancelling'],
      paused: ['neutral', 'Paused'],
      interrupted: ['attention', 'Interrupted'],
      applied: ['informational', 'Applied'],
      validating: ['waiting', 'Validating'],
      validated: ['success', 'Validated'],
      completed_without_change: ['neutral', 'No changes'],
      rejected: ['neutral', 'Rejected'],
      cancelled: ['neutral', 'Cancelled'],
      blocked: ['blocked', 'Blocked'],
      unavailable: ['blocked', 'Unavailable'],
      failed: ['danger', 'Failed'],
      human_accepted: ['success', 'Accepted'],
    }
    for (const state of ALL_OPERATION_STATES) {
      const p = operationStatePresentation(state)
      expect([p.state, p.label]).toEqual(expected[state])
      expect(p.icon).toBeTruthy()
    }
    // Spinners only for in-flight states.
    expect(operationStatePresentation('running').spin).toBe(true)
    expect(operationStatePresentation('preparing').spin).toBe(true)
    expect(operationStatePresentation('validating').spin).toBe(true)
    expect(operationStatePresentation('approved').spin).toBeUndefined()
  })

  it('renders no badge for available capabilities (design.md §7.2)', () => {
    expect(capabilityPresentation('available')).toBeNull()
    expect(capabilityPresentation('degraded')?.state).toBe('attention')
    expect(capabilityPresentation('environment_gated')?.state).toBe('neutral')
    expect(capabilityPresentation('unavailable')?.state).toBe('blocked')
  })

  it('maps VM/SSH/health states honestly (never red for merely stopped)', () => {
    expect(vmStatePresentation('stopped').state).toBe('neutral')
    expect(vmStatePresentation('running').state).toBe('success')
    expect(vmStatePresentation('unavailable').state).toBe('blocked')
    expect(sshStatePresentation('unavailable_vm_stopped').state).toBe('neutral')
    expect(sshStatePresentation('failed').state).toBe('danger')
    expect(healthStatePresentation('not_checked').state).toBe('attention')
    expect(healthStatePresentation('healthy').state).toBe('success')
  })

  it('maps instance health without color-only semantics', () => {
    expect(instanceHealthPresentation('ready')).toMatchObject({ state: 'success', label: 'Ready' })
    expect(instanceHealthPresentation('attention_needed').state).toBe('attention')
    expect(instanceHealthPresentation('blocked').state).toBe('blocked')
  })

  it('keeps receipt outcome and validation evidence visually distinct', () => {
    expect(receiptResultPresentation('applied')).toMatchObject({ state: 'informational', label: 'Applied' })
    expect(receiptResultPresentation('executed')).toMatchObject({ state: 'informational', label: 'Executed' })
    expect(receiptResultPresentation('completed')).toMatchObject({ state: 'informational', label: 'Completed' })
    expect(receiptResultPresentation('validated')).toMatchObject({ state: 'success', label: 'Validated' })
    expect(receiptResultPresentation('human_accepted')).toMatchObject({ state: 'success', label: 'Accepted' })
    expect(receiptValidationPresentation('not_recorded')).toMatchObject({ state: 'neutral', label: 'Not recorded' })
    expect(receiptValidationPresentation('validated')).toMatchObject({ state: 'success', label: 'Validated' })
  })
})
