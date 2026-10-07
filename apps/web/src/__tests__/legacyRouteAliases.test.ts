/**
 * Machine-declared legacy route aliases remain honest redirects to the
 * application-first React routes. Instance identity and query state survive
 * normalization; malformed or invented variants remain NotFound candidates.
 */
import { describe, expect, it } from 'vitest'

import { normalizeLegacyHash } from '../legacyRoutes'

describe('machine-declared legacy route aliases', () => {
  it.each([
    ['#instances', '#/applications'],
    ['#instance/ins_project', '#/app/ins_project'],
    ['#conversation/ins_project', '#/app/ins_project/conversation'],
    ['#advanced/ins_project', '#/app/ins_project/settings'],
    ['#workbench/ins_project', '#/app/ins_project/workbench'],
    ['#advanced', '#/settings'],
  ])('resolves %s to its current equivalent', (legacy, current) => {
    expect(normalizeLegacyHash(legacy)).toBe(current)
  })

  it.each([
    [
      '#conversation/ins_project?message=msg_42&from=telegram',
      '#/app/ins_project/conversation?message=msg_42&from=telegram',
    ],
    ['#advanced/ins_project?group=technical', '#/app/ins_project/settings?group=technical'],
    ['#workbench/ins_project?layout=focus', '#/app/ins_project/workbench?layout=focus'],
  ])('preserves instance and query identity for %s', (legacy, current) => {
    expect(normalizeLegacyHash(legacy)).toBe(current)
  })

  it.each([
    '#instance',
    '#instance/',
    '#conversation/',
    '#advanced/',
    '#workbench/',
    '#conversation/ins_project/unknown',
    '#workbench/ins_project/terminal',
  ])('does not invent an equivalent for malformed or undeclared alias %s', (legacy) => {
    expect(normalizeLegacyHash(legacy)).toBe(legacy)
  })
})
