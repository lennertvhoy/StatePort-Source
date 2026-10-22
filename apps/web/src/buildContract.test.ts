import { describe, expect, it } from 'vitest'

import {
  resolveWebBuildProvenance,
  resolveWebBuildContract,
  WEB_BUILD_IDENTITY_FORMAT,
} from './buildContract'

describe('distributable web build contract', () => {
  const unknownProvenance = {
    sourceCommit: 'unknown',
    sourceTree: 'unknown',
    sourceRef: 'unknown',
    sourceDirty: true,
    builtAt: 'unknown',
  }

  it('binds the production output to the HTTP adapter', () => {
    expect(resolveWebBuildContract('production', undefined)).toEqual({
      outDir: 'dist',
      identity: {
        formatVersion: WEB_BUILD_IDENTITY_FORMAT,
        adapter: 'http',
        mode: 'production',
        ...unknownProvenance,
      },
    })
    expect(resolveWebBuildContract('production', 'http').identity.adapter).toBe(
      'http',
    )
  })

  it('isolates the demo output and binds it to the mock adapter', () => {
    expect(resolveWebBuildContract('demo', 'mock')).toEqual({
      outDir: 'dist-demo',
      identity: {
        formatVersion: WEB_BUILD_IDENTITY_FORMAT,
        adapter: 'mock',
        mode: 'demo',
        ...unknownProvenance,
      },
    })
  })

  it.each([
    ['production', 'mock'],
    ['demo', 'http'],
  ])('rejects a %s build with the %s adapter', (mode, adapter) => {
    expect(() => resolveWebBuildContract(mode, adapter)).toThrow(
      /requires the (HTTP|mock) adapter/,
    )
  })

  it('rejects an undeclared distributable mode', () => {
    expect(() => resolveWebBuildContract('staging', undefined)).toThrow(
      /only production and demo modes/,
    )
  })

  it('accepts exact source identity and a deterministic supplied time', () => {
    expect(
      resolveWebBuildProvenance({
        sourceCommit: 'a'.repeat(40),
        sourceTree: 'b'.repeat(40),
        sourceRef: 'refs/heads/release/v1',
        sourceDirty: 'false',
        sourceDateEpoch: '0',
      }),
    ).toEqual({
      sourceCommit: 'a'.repeat(40),
      sourceTree: 'b'.repeat(40),
      sourceRef: 'refs/heads/release/v1',
      sourceDirty: false,
      builtAt: '1970-01-01T00:00:00.000Z',
    })
  })

  it('defaults unavailable provenance to unknown and dirty', () => {
    expect(resolveWebBuildProvenance()).toEqual(unknownProvenance)
  })

  it.each([
    [{ sourceCommit: 'abc' }, /exact lowercase 40-hex/],
    [{ sourceCommit: 'A'.repeat(40) }, /exact lowercase 40-hex/],
    [{ sourceCommit: 'a'.repeat(40) }, /commit and tree/],
    [{ sourceTree: 'b'.repeat(40) }, /commit and tree/],
    [{ sourceCommit: 'a'.repeat(40), sourceTree: 'abc' }, /exact lowercase 40-hex/],
    [{ sourceCommit: 'unknown', sourceTree: 'unknown', sourceDirty: false }, /unknown source commit/],
    [{ sourceDirty: 'clean' }, /exactly true or false/],
    [{ sourceRef: 'refs/heads/has space' }, /source ref/],
    [{ sourceDateEpoch: '-1' }, /SOURCE_DATE_EPOCH/],
    [{ sourceDateEpoch: '1.5' }, /SOURCE_DATE_EPOCH/],
  ])('rejects invalid or misleading provenance %#', (input, message) => {
    expect(() => resolveWebBuildProvenance(input)).toThrow(message)
  })
})
