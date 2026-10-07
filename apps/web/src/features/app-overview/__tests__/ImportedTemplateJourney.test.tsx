import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it } from 'vitest'

import { buildSeed } from '@/client/mock/seed'
import { ImportedTemplateJourney } from '../components/ImportedTemplateJourney'

afterEach(cleanup)

it('guides an isolated template to resolved runs and receipts without promising a state change', () => {
  const instance = buildSeed().instances.find(({ id }) => id === 'ins_study_alpha')!
  render(<MemoryRouter><ImportedTemplateJourney instance={{
    ...instance, provenance: { source: { management: 'isolated_template' } },
  }} /></MemoryRouter>)
  expect(screen.getByRole('link', { name: 'Review first inspection' }).getAttribute('href')).toBe(`/app/${instance.id}/runs`)
  expect(screen.getByRole('link', { name: 'Inspect durable receipts' }).getAttribute('href')).toBe(`/app/${instance.id}/receipts`)
  expect(screen.getByText(/does not change your template/)).toBeTruthy()
})

it('does not suggest a template action for an ordinary application', () => {
  const instance = buildSeed().instances[0]
  render(<MemoryRouter><ImportedTemplateJourney instance={{ ...instance, provenance: undefined }} /></MemoryRouter>)
  expect(screen.queryByRole('region', { name: 'First task with this template' })).toBeNull()
})
