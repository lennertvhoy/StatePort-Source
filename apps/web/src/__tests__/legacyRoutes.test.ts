/**
 * Legacy hash normalization (binding doc §10): the legacy route forms are
 * rewritten before the router renders; normal hashes pass through untouched.
 */
import { describe, expect, it } from 'vitest'

import { normalizeLegacyHash } from '../legacyRoutes'

describe('normalizeLegacyHash', () => {
  it.each([
    ['#home', '#/applications'],
    ['#catalog', '#/catalog'],
    ['#approvals', '#/approvals'],
    ['#settings', '#/settings'],
    ['#platform', '#/applications'],
    // #app/<id> gets the slash inserted.
    ['#app/ins_nixos', '#/app/ins_nixos'],
    // Subpaths are preserved.
    ['#app/ins_nixos/workbench/receipts', '#/app/ins_nixos/workbench/receipts'],
    // Query strings ride along.
    ['#app/ins_nixos?scenario=lab', '#/app/ins_nixos?scenario=lab'],
    ['#home?scenario=lab', '#/applications?scenario=lab'],
  ])('rewrites %s → %s', (input, expected) => {
    expect(normalizeLegacyHash(input)).toBe(expected)
  })

  it.each([
    // Already-normal hashes pass through untouched.
    ['#/applications', '#/applications'],
    ['#/app/ins_nixos/workbench/files', '#/app/ins_nixos/workbench/files'],
    ['#/app/ins_nixos?scenario=lab', '#/app/ins_nixos?scenario=lab'],
    // Unknown legacy hashes are left for the router's NotFound handling.
    ['#bogus', '#bogus'],
    // Empty / bare hashes are untouched.
    ['', ''],
    ['#', '#'],
  ])('leaves %s unchanged', (input, expected) => {
    expect(normalizeLegacyHash(input)).toBe(expected)
  })
})
