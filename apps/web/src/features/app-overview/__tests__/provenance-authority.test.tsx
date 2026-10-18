import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { ProvenanceOwnershipSection } from '../components/ProvenanceOwnershipSection'


describe('provenance authority presentation', () => {
  it('shows effective candidate access instead of inflating the declared source class', async () => {
    const user = userEvent.setup()
    render(
      <ProvenanceOwnershipSection
        provenance={{
          source: {
            repository: 'https://github.com/example/study-state.git',
            resolvedCommit: 'a'.repeat(40),
            resolvedTree: 'b'.repeat(40),
            manifestDigest: `sha256:${'c'.repeat(64)}`,
            sourceDigest: `sha256:${'d'.repeat(64)}`,
            sourceClass: 'canonical_source',
            productionEligible: true,
            sourceAccessClass: 'development_candidate',
            productionInstallAllowed: false,
          },
        }}
      />,
    )

    expect(screen.getByText('Development candidate - local testing only')).toBeTruthy()
    expect(screen.getByText(/Production installation remains blocked/)).toBeTruthy()
    await user.click(screen.getByRole('button', { name: /exact identity and bounded paths/i }))
    expect(screen.getByText('development_candidate')).toBeTruthy()
    expect(screen.getByText('blocked')).toBeTruthy()
  })

  it('does not present a declared canonical source as effective release access', () => {
    render(
      <ProvenanceOwnershipSection
        provenance={{
          source: {
            resolvedCommit: 'a'.repeat(40),
            resolvedTree: 'b'.repeat(40),
            manifestDigest: `sha256:${'c'.repeat(64)}`,
            sourceClass: 'canonical_source',
            productionEligible: true,
          },
        }}
      />,
    )

    expect(screen.getByText('Canonical source - access not recorded')).toBeTruthy()
    expect(screen.getByText(/no effective source-access grant is recorded/i)).toBeTruthy()
  })
})
