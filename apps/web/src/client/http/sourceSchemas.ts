/**
 * Canonical-source wire contracts.
 *
 * These schemas are deliberately strict. The public projection must never
 * accept repository/candidate/path evidence, while the operator projection
 * accepts only the exact redacted fields emitted by the service.
 */
import { z } from 'zod'

import type {
  CanonicalSourceOperatorView,
  CanonicalSourcePublicView,
  DevelopmentSourceResolution,
  DevelopmentSourceVerificationInput,
} from '../types'

const sourceId = z.string().regex(/^[a-z0-9][a-z0-9._-]{1,159}$/)
const gitObjectId = z.string().regex(/^[0-9a-f]{40}$/)
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/)
const nonEmpty = z.string().min(1)
const remoteRepository = z
  .string()
  .regex(/^(?:https|ssh):\/\/(?![^/?#]*@)[^/?#:@]+(?::[0-9]+)?(?:\/[^?#]*)?$/)

const canonicalSourceStatus = z.enum([
  'awaiting_verified_release',
  'source_available',
  'rejected',
])

const sourceIdentity = z
  .object({
    repository: remoteRepository,
    commit: gitObjectId,
    tree: gitObjectId,
    manifestDigest: digest,
    sourceDigest: digest,
  })
  .strict()

export const canonicalSourcePublicViewSchema: z.ZodType<CanonicalSourcePublicView> = z
  .object({
    formatVersion: z.literal('stateport.canonical-source-public-view/v1'),
    sourceId,
    applicationId: nonEmpty,
    publicName: nonEmpty,
    status: canonicalSourceStatus,
    installable: z.boolean(),
    productionAction: z
      .object({
        action: z.literal('install_or_update'),
        enabled: z.boolean(),
      })
      .strict(),
    message: nonEmpty,
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.installable !== value.productionAction.enabled) {
      ctx.addIssue({
        code: 'custom',
        path: ['productionAction', 'enabled'],
        message: 'production action availability must match source installability',
      })
    }
  })

export const canonicalSourceIndexSchema = z
  .object({
    sources: z.array(canonicalSourcePublicViewSchema),
  })
  .strict()
  .superRefine((value, ctx) => {
    const ids = value.sources.map((source) => source.sourceId)
    if (new Set(ids).size !== ids.length) {
      ctx.addIssue({
        code: 'custom',
        path: ['sources'],
        message: 'source identities must be unique',
      })
    }
  })

const canonicalRelease = z
  .object({
    sourceClass: z.literal('canonical_release'),
    identity: sourceIdentity.nullable(),
    status: canonicalSourceStatus,
    trust: z.enum(['unverified', 'development_only', 'verified_release', 'rejected']),
    installable: z.boolean(),
    missingRequirement: nonEmpty.nullable(),
    requiredModules: z.array(nonEmpty),
    expectedSelfTests: z.array(nonEmpty),
  })
  .strict()

const developmentCandidate = z
  .object({
    sourceClass: z.literal('development_candidate'),
    releaseStatus: z.literal('candidate'),
    testingAllowed: z.boolean(),
    productionInstallAllowed: z.literal(false),
    identity: sourceIdentity,
    verifiedModules: z.array(nonEmpty),
    verifiedSelfTests: z.array(nonEmpty),
    verificationAction: z
      .object({
        enabled: z.boolean(),
        acknowledgement: digest,
        purpose: z.literal('isolated_development_verification_only'),
      })
      .strict(),
  })
  .strict()

export const canonicalSourceOperatorViewSchema: z.ZodType<CanonicalSourceOperatorView> = z
  .object({
    formatVersion: z.literal('stateport.canonical-source-operator-view/v1'),
    sourceId,
    application: z
      .object({
        id: nonEmpty,
        publicName: nonEmpty,
        legacyIdentifiers: z.array(nonEmpty),
      })
      .strict(),
    authority: z
      .object({
        repository: remoteRepository,
        canonicalRefPolicy: nonEmpty,
        manifestPath: nonEmpty,
        manifestContract: nonEmpty,
      })
      .strict(),
    canonicalRelease,
    developmentCandidate: developmentCandidate.nullable(),
    message: nonEmpty,
  })
  .strict()
  .superRefine((value, ctx) => {
    const identities = [
      value.canonicalRelease.identity,
      value.developmentCandidate?.identity ?? null,
    ].filter((identity): identity is NonNullable<typeof identity> => identity !== null)
    if (identities.some((identity) => identity.repository !== value.authority.repository)) {
      ctx.addIssue({
        code: 'custom',
        path: ['authority', 'repository'],
        message: 'source identities must match the declared repository authority',
      })
    }
    if (
      value.canonicalRelease.installable &&
      (value.canonicalRelease.status !== 'source_available' ||
        value.canonicalRelease.trust !== 'verified_release' ||
        value.canonicalRelease.identity === null)
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['canonicalRelease', 'installable'],
        message: 'installable canonical sources require an exact verified release identity',
      })
    }
  })

export const developmentSourceResolutionSchema: z.ZodType<DevelopmentSourceResolution> = z
  .object({
    formatVersion: z.literal('stateport.development-source-resolution/v1'),
    sourceId,
    applicationId: nonEmpty,
    sourceClass: z.literal('development_candidate'),
    identity: sourceIdentity,
    releaseStatus: z.literal('candidate'),
    trust: z.literal('development_only'),
    productionInstallAllowed: z.literal(false),
    verifiedModules: z.array(nonEmpty),
    requiredSelfTests: z.array(nonEmpty),
    selfTestDeclarationsMatched: z.boolean(),
    selfTestsExecutedByThisOperation: z.boolean(),
    verifiedAt: z.string().datetime({ offset: true }),
    receiptDigest: digest,
  })
  .strict()

export const developmentSourceVerificationInputSchema: z.ZodType<DevelopmentSourceVerificationInput> = z
  .object({
    sourceId,
    sourceClass: z.literal('development_candidate'),
    expectedCommit: gitObjectId,
    expectedTree: gitObjectId,
    expectedManifestDigest: digest,
    expectedSourceDigest: digest,
    acknowledgement: digest,
  })
  .strict()
