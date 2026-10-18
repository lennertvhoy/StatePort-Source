export const WEB_BUILD_IDENTITY_FILENAME = 'stateport-build.json'
export const WEB_BUILD_IDENTITY_FORMAT = 'stateport.web-build/v3'
export const UNKNOWN_WEB_BUILD_IDENTITY = 'unknown'

export type WebBuildAdapter = 'http' | 'mock'
export type WebBuildMode = 'production' | 'demo'

export interface WebBuildProvenance {
  sourceCommit: string
  sourceTree: string
  sourceRef: string
  sourceDirty: boolean
  builtAt: string
}

export interface WebBuildIdentity {
  formatVersion: typeof WEB_BUILD_IDENTITY_FORMAT
  adapter: WebBuildAdapter
  mode: WebBuildMode
  sourceCommit: string
  sourceTree: string
  sourceRef: string
  sourceDirty: boolean
  builtAt: string
}

export interface WebBuildContract {
  outDir: 'dist' | 'dist-demo'
  identity: WebBuildIdentity
}

export interface WebBuildProvenanceInput {
  sourceCommit?: string
  sourceTree?: string
  sourceRef?: string
  sourceDirty?: boolean | string
  sourceDateEpoch?: string
}

const EXACT_COMMIT = /^[0-9a-f]{40}$/
const NON_AUTHORITATIVE_REF = /^[A-Za-z0-9._/@:+-]{1,200}$/
const SOURCE_DATE_EPOCH = /^(0|[1-9][0-9]{0,11})$/

/**
 * Validate source identity without manufacturing a clean revision.
 *
 * `sourceRef` is display/provenance metadata only. The `sourceCommit` and
 * `sourceTree` pair is the authoritative source identity when present. A
 * build without that exact pair is necessarily dirty/unknown, even if a
 * caller claims otherwise.
 */
export function resolveWebBuildProvenance(
  input: WebBuildProvenanceInput = {},
): WebBuildProvenance {
  const sourceCommit =
    input.sourceCommit?.trim() || UNKNOWN_WEB_BUILD_IDENTITY
  if (
    sourceCommit !== UNKNOWN_WEB_BUILD_IDENTITY &&
    !EXACT_COMMIT.test(sourceCommit)
  ) {
    throw new Error(
      'StatePort build source commit must be an exact lowercase 40-hex Git commit.',
    )
  }

  const sourceTree = input.sourceTree?.trim() || UNKNOWN_WEB_BUILD_IDENTITY
  if (
    sourceTree !== UNKNOWN_WEB_BUILD_IDENTITY &&
    !EXACT_COMMIT.test(sourceTree)
  ) {
    throw new Error(
      'StatePort build source tree must be an exact lowercase 40-hex Git tree.',
    )
  }
  if (
    (sourceCommit === UNKNOWN_WEB_BUILD_IDENTITY) !==
    (sourceTree === UNKNOWN_WEB_BUILD_IDENTITY)
  ) {
    throw new Error(
      'StatePort build source commit and tree must both be exact or both be unknown.',
    )
  }

  const sourceRef = input.sourceRef?.trim() || UNKNOWN_WEB_BUILD_IDENTITY
  if (
    sourceRef !== UNKNOWN_WEB_BUILD_IDENTITY &&
    !NON_AUTHORITATIVE_REF.test(sourceRef)
  ) {
    throw new Error(
      'StatePort build source ref contains unsupported characters or is too long.',
    )
  }

  let sourceDirty: boolean
  if (typeof input.sourceDirty === 'boolean') {
    sourceDirty = input.sourceDirty
  } else if (
    input.sourceDirty === undefined ||
    input.sourceDirty.trim() === ''
  ) {
    sourceDirty = true
  } else if (input.sourceDirty === 'true') {
    sourceDirty = true
  } else if (input.sourceDirty === 'false') {
    sourceDirty = false
  } else {
    throw new Error(
      'StatePort build dirty identity must be exactly true or false.',
    )
  }
  if (sourceCommit === UNKNOWN_WEB_BUILD_IDENTITY && !sourceDirty) {
    throw new Error(
      'StatePort cannot identify an unknown source commit as clean.',
    )
  }

  const epoch = input.sourceDateEpoch?.trim()
  let builtAt = UNKNOWN_WEB_BUILD_IDENTITY
  if (epoch) {
    if (!SOURCE_DATE_EPOCH.test(epoch)) {
      throw new Error(
        'SOURCE_DATE_EPOCH must be a non-negative integer number of seconds.',
      )
    }
    try {
      builtAt = new Date(Number(epoch) * 1_000).toISOString()
    } catch {
      throw new Error('SOURCE_DATE_EPOCH is outside the supported date range.')
    }
    if (!/^[0-9]{4}-/.test(builtAt)) {
      throw new Error('SOURCE_DATE_EPOCH is outside the supported date range.')
    }
  }

  return {
    sourceCommit,
    sourceTree,
    sourceRef,
    sourceDirty,
    builtAt,
  }
}

/**
 * Resolve the only two distributable frontend shapes.
 *
 * Production output is always the same-origin HTTP client. A mock artifact is
 * deliberately a demo build with a different output directory and identity;
 * an ambient or mode-specific override may never blur that boundary.
 */
export function resolveWebBuildContract(
  mode: string,
  requestedAdapter: string | undefined,
  provenance: WebBuildProvenance = resolveWebBuildProvenance(),
): WebBuildContract {
  if (mode !== 'production' && mode !== 'demo') {
    throw new Error(
      'StatePort distributable web builds support only production and demo modes.',
    )
  }

  const adapter: WebBuildAdapter = mode === 'demo' ? 'mock' : 'http'
  if (requestedAdapter && requestedAdapter !== adapter) {
    throw new Error(
      mode === 'demo'
        ? 'The StatePort demo build requires the mock adapter.'
        : 'The StatePort production build requires the HTTP adapter; unset VITE_STATEPORT_ADAPTER or set it to http.',
    )
  }

  return {
    outDir: mode === 'demo' ? 'dist-demo' : 'dist',
    identity: {
      formatVersion: WEB_BUILD_IDENTITY_FORMAT,
      adapter,
      mode,
      ...provenance,
    },
  }
}
