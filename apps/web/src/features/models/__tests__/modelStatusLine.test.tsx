/** The AI-model status line on the Applications page: honest about what the service said. */
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it } from 'vitest'

import { setModelsClientForTests } from '@/client/modelsClient'
import { ClientError } from '@/client/types'

import { ModelStatusLine } from '../ModelStatusLine'
import { FREE, consentedProjection, fakeModelsClient, modelsView, routedWithoutConsent } from './fakeModels'

afterEach(() => {
  cleanup()
  setModelsClientForTests(null)
})

function renderLine(view: ReturnType<typeof modelsView> | (() => Promise<ReturnType<typeof modelsView>>)) {
  setModelsClientForTests(fakeModelsClient(view as never))
  return render(<MemoryRouter><ModelStatusLine /></MemoryRouter>)
}

describe('AI-model status line', () => {
  it('names the model an agent action uses, and links to Settings → Models', async () => {
    renderLine(modelsView(consentedProjection()))
    await waitFor(() => expect(screen.getByTestId('model-status-line').getAttribute('data-state')).toBe('ready'))
    expect(screen.getByTestId('model-status-line').textContent).toContain(`Agent actions use ${FREE}`)
    expect(screen.getByTestId('model-status-link').getAttribute('href')).toBe('/settings/models')
  })

  it('says free models are off until the terms are accepted', async () => {
    renderLine(modelsView(routedWithoutConsent()))
    await waitFor(() => expect(screen.getByTestId('model-status-line').getAttribute('data-state')).toBe('off'))
    expect(screen.getByTestId('model-status-line').textContent).toContain('Free models are off')
  })

  it('says "unknown" when the service cannot be read, never "ready"', async () => {
    setModelsClientForTests(fakeModelsClient(() => Promise.reject(new ClientError('network', 'offline'))))
    render(<MemoryRouter><ModelStatusLine /></MemoryRouter>)
    await waitFor(() => expect(screen.getByTestId('model-status-line').getAttribute('data-state')).toBe('unknown'))
    expect(screen.getByTestId('model-status-line').textContent).toContain('could not read its model routes')
    expect(screen.getByTestId('model-status-line').textContent).not.toContain('ready')
  })
})
