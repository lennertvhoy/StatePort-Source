/**
 * Governed file-workspace response-integrity tests.
 *
 * A successful HTTP mutation is not sufficient evidence by itself: the
 * adapter accepts a commit only when its receipt binds the exact reviewed
 * operation, application, path, Git base, content hashes, and diff digest.
 */
import { describe, expect, it } from 'vitest'

import { ClientError } from '../../types'
import { HttpFilesClient } from '../domainsCore'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const BASE_SHA = 'a'.repeat(40)
const BEFORE_HASH = `sha256:${'b'.repeat(64)}`
const AFTER_HASH = `sha256:${'c'.repeat(64)}`
const DIFF_DIGEST = `sha256:${'d'.repeat(64)}`
const PATH = 'README.md'

function makeCommitReceipt(overrides: Record<string, unknown> = {}) {
  return {
    formatVersion: 'stateport.file-workspace/v1',
    receiptId: 'file-receipt-1',
    operation: 'commitWrite',
    actorId: 'local-user',
    instanceId: 'ins_1',
    applicationId: 'stateport.projectstate',
    sourcePath: PATH,
    destinationPath: null,
    baseSha: BASE_SHA,
    preHash: BEFORE_HASH,
    postHash: AFTER_HASH,
    ownershipClass: 'application_owned',
    diffDigest: DIFF_DIGEST,
    validation: 'passed',
    completedAt: '2026-07-19T09:00:00.000Z',
    contentRetained: false,
    ...overrides,
  }
}

function listing(entries: Array<Record<string, unknown>>) {
  return {
    operation: 'listDirectory',
    path: '',
    baseSha: BASE_SHA,
    truncated: false,
    entries,
  }
}

function read(
  path: string,
  content: string,
  contentHash: string,
  baseSha = BASE_SHA,
) {
  return {
    formatVersion: 'stateport.file-workspace/v1',
    operation: 'readFile',
    content,
    metadata: {
      formatVersion: 'stateport.file-workspace/v1',
      operation: 'readFileMetadata',
      path,
      size: new TextEncoder().encode(content).byteLength,
      contentHash,
      baseSha,
      ownershipClass: 'application_owned',
      language: path.endsWith('.md') ? 'markdown' : 'text',
      readOnly: false,
      encoding: 'utf-8',
      generated: false,
      disposable: false,
    },
  }
}

function mutationReceipt(
  operation: 'createFile' | 'renamePath' | 'deletePath',
  overrides: Record<string, unknown> = {},
) {
  return {
    formatVersion: 'stateport.file-workspace/v1',
    operation,
    receiptId: `file-${operation}-1`,
    actorId: 'local-user',
    applicationId: 'stateport.projectstate',
    instanceId: 'ins_1',
    sourcePath: PATH,
    destinationPath: null,
    baseSha: BASE_SHA,
    preHash: BEFORE_HASH,
    postHash: AFTER_HASH,
    ownershipClass: 'application_owned',
    diffDigest: null,
    validation: 'not_required',
    completedAt: '2026-07-19T09:00:00.000Z',
    contentRetained: false,
    ...overrides,
  }
}

function makeFiles(
  commitReceipt: Record<string, unknown>,
  readback: {
    content?: string
    contentHash?: string
    baseSha?: string
  } = {},
) {
  let reads = 0
  const fake = makeFakeFetch([
    [
      'GET',
      '/v1/instances/ins_1/file-workspace/readFile',
      () => {
        reads += 1
        return jsonResponse(
          reads === 1
            ? read(PATH, 'before\n', BEFORE_HASH)
            : read(
                PATH,
                readback.content ?? 'after\n',
                readback.contentHash ?? AFTER_HASH,
                readback.baseSha ?? BASE_SHA,
              ),
        )
      },
    ],
    [
      'POST',
      '/v1/instances/ins_1/file-workspace/prepareWrite',
      jsonResponse({
        formatVersion: 'stateport.file-workspace/v1',
        operation: 'prepareWrite',
        writeKind: 'write',
        preparedWriteId: 'prepared-1',
        path: PATH,
        actorId: 'local-user',
        applicationId: 'stateport.projectstate',
        instanceId: 'ins_1',
        originalHash: BEFORE_HASH,
        candidateHash: AFTER_HASH,
        baseSha: BASE_SHA,
        ownershipClass: 'application_owned',
        expiresAt: '2026-07-19T09:05:00.000Z',
        requiresDiffConfirmation: true,
        validationRequired: true,
      }),
    ],
    [
      'POST',
      '/v1/instances/ins_1/file-workspace/previewDiff',
      jsonResponse({
        formatVersion: 'stateport.file-workspace/v1',
        operation: 'previewDiff',
        preparedWriteId: 'prepared-1',
        path: PATH,
        diff: '--- a/README.md\n+++ b/README.md\n-before\n+after\n',
        diffDigest: DIFF_DIGEST,
        originalHash: BEFORE_HASH,
        candidateHash: AFTER_HASH,
        truncated: false,
        confirmable: true,
      }),
    ],
    [
      'POST',
      '/v1/instances/ins_1/file-workspace/commitWrite',
      jsonResponse(commitReceipt),
    ],
  ])
  return {
    fake,
    files: new HttpFilesClient(new HttpTransport({ fetchFn: fake.fetchFn })),
  }
}

describe('HttpFilesClient commit receipt identity', () => {
  it('accepts only the complete reviewed receipt and exact readback basis', async () => {
    const { fake, files } = makeFiles(makeCommitReceipt())
    await files.read('ins_1', PATH)

    const result = await files.write('ins_1', PATH, {
      content: 'after\n',
      expectedRevision: BEFORE_HASH,
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.change).toMatchObject({
      path: PATH,
      beforeRevision: BEFORE_HASH,
      afterRevision: AFTER_HASH,
    })
    expect(result.receipt).toMatchObject({
      id: 'file-receipt-1',
      instanceId: 'ins_1',
      packageId: 'stateport.projectstate',
      expectedRevision: BEFORE_HASH,
      resultRevision: AFTER_HASH,
      payloadDigest: { algorithm: 'sha256', value: DIFF_DIGEST },
    })
    expect(fake.callsTo('/file-workspace/commitWrite')[0].body).toEqual({
      preparedWriteId: 'prepared-1',
      confirmedDiffDigest: DIFF_DIGEST,
    })
  })

  it.each([
    ['a different Git base', { baseSha: 'e'.repeat(40) }],
    ['a different operation', { operation: 'createFile' }],
    ['a different application', { applicationId: 'stateport.other' }],
    ['a different instance', { instanceId: 'ins_other' }],
    ['a different path', { sourcePath: 'OTHER.md' }],
    ['a different prior revision', { preHash: `sha256:${'e'.repeat(64)}` }],
    ['a different result revision', { postHash: `sha256:${'e'.repeat(64)}` }],
    ['a different diff digest', { diffDigest: `sha256:${'e'.repeat(64)}` }],
    ['a different actor', { actorId: 'other-user' }],
    ['a different ownership class', { ownershipClass: 'disposable' }],
    ['an unexpected destination', { destinationPath: 'OTHER.md' }],
    ['a mismatched validation result', { validation: 'not_required' }],
  ])('rejects a receipt bound to %s', async (_label, overrides) => {
    const { fake, files } = makeFiles(makeCommitReceipt(overrides))
    await files.read('ins_1', PATH)

    const error = await files
      .write('ins_1', PATH, {
        content: 'after\n',
        expectedRevision: BEFORE_HASH,
      })
      .catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
    expect((error as ClientError).message).toContain(
      'committed file receipt did not match',
    )
    expect(
      fake.callsTo('/v1/instances/ins_1/file-workspace/commitWrite')[0].headers[
        'x-stateport-csrf'
      ],
    ).toBe('test-csrf')
  })

  it.each([
    ['missing format identity', { formatVersion: undefined }],
    ['missing actor identity', { actorId: undefined }],
    ['missing content-retention evidence', { contentRetained: undefined }],
    ['retained content', { contentRetained: true }],
    ['failed validation', { validation: 'failed' }],
    ['an empty receipt identity', { receiptId: '' }],
    ['an invalid completion time', { completedAt: 'sometime' }],
  ])('rejects a malformed receipt with %s', async (_label, overrides) => {
    const { files } = makeFiles(makeCommitReceipt(overrides))
    await files.read('ins_1', PATH)
    await expect(files.write('ins_1', PATH, {
      content: 'after\n',
      expectedRevision: BEFORE_HASH,
    })).rejects.toMatchObject({
      kind: 'validation',
      message: expect.stringContaining('file mutation receipt'),
    })
  })

  it.each([
    ['stale readback revision', { contentHash: BEFORE_HASH }],
    ['different readback content', { content: 'not the committed bytes\n' }],
    ['changed readback Git base', { baseSha: 'e'.repeat(40) }],
  ])('rejects %s after the commit receipt', async (_label, readback) => {
    const { files } = makeFiles(makeCommitReceipt(), readback)
    await files.read('ins_1', PATH)
    await expect(files.write('ins_1', PATH, {
      content: 'after\n',
      expectedRevision: BEFORE_HASH,
    })).rejects.toMatchObject({
      kind: 'validation',
      message: expect.stringContaining('could not be read back'),
    })
  })
})

describe('HttpFilesClient governed path mutations', () => {
  it('creates only after a complete tree basis and exact reviewed create receipt', async () => {
    const createdPath = 'notes/new.md'
    let listingCalls = 0
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/file-workspace/listDirectory', () => {
        listingCalls += 1
        return jsonResponse(listingCalls === 1 ? listing([]) : listing([
          { path: createdPath, name: 'new.md', kind: 'file', size: 6, readOnly: false },
        ]))
      }],
      ['POST', '/v1/instances/ins_1/file-workspace/createFile', jsonResponse({
        operation: 'createFile',
        writeKind: 'create',
        preparedWriteId: 'prepared-create-1',
        path: createdPath,
        actorId: 'local-user',
        applicationId: 'stateport.projectstate',
        instanceId: 'ins_1',
        baseSha: BASE_SHA,
        originalHash: null,
        candidateHash: AFTER_HASH,
        ownershipClass: 'application_owned',
        expiresAt: '2026-07-19T09:05:00.000Z',
        requiresDiffConfirmation: true,
        validationRequired: false,
      })],
      ['POST', '/v1/instances/ins_1/file-workspace/previewDiff', jsonResponse({
        operation: 'previewDiff',
        preparedWriteId: 'prepared-create-1',
        path: createdPath,
        diff: '--- /dev/null\n+++ b/notes/new.md\n+hello\n',
        diffDigest: DIFF_DIGEST,
        originalHash: null,
        candidateHash: AFTER_HASH,
        truncated: false,
        confirmable: true,
      })],
      ['POST', '/v1/instances/ins_1/file-workspace/commitWrite', jsonResponse(mutationReceipt('createFile', {
        sourcePath: createdPath,
        preHash: null,
        postHash: AFTER_HASH,
        diffDigest: DIFF_DIGEST,
        validation: 'not_required',
      }))],
      ['GET', '/v1/instances/ins_1/file-workspace/readFile', jsonResponse(read(createdPath, 'hello\n', AFTER_HASH))],
    ])
    const files = new HttpFilesClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(files.create('ins_1', createdPath, { content: 'hello\n' })).rejects.toMatchObject({
      kind: 'validation',
      message: expect.stringContaining('tree must be listed'),
    })
    await files.listTree('ins_1')
    const result = await files.create('ins_1', createdPath, { content: 'hello\n' })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.entry.path).toBe(createdPath)
    expect(result.diff.addedLines).toBe(1)
    expect(result.receipt.id).toBe('file-createFile-1')
    expect(fake.callsTo('/file-workspace/createFile')[0].body).toEqual({
      path: createdPath,
      content: 'hello\n',
      expectedBaseSha: BASE_SHA,
    })
    expect(fake.callsTo('/file-workspace/commitWrite')[0].body).toEqual({
      preparedWriteId: 'prepared-create-1',
      confirmedDiffDigest: DIFF_DIGEST,
    })
  })

  it('renames and deletes only from the exact read basis', async () => {
    const renamedPath = 'RENAMED.md'
    let currentPath = PATH
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/file-workspace/readFile', (call) => {
        const path = new URL(call.url, 'http://stateport.test').searchParams.get('path')
        if (path === renamedPath) return jsonResponse(read(renamedPath, 'before\n', BEFORE_HASH))
        return jsonResponse(read(PATH, 'before\n', BEFORE_HASH))
      }],
      ['POST', '/v1/instances/ins_1/file-workspace/renamePath', () => {
        currentPath = renamedPath
        return jsonResponse(mutationReceipt('renamePath', {
          sourcePath: PATH,
          destinationPath: renamedPath,
          preHash: BEFORE_HASH,
          postHash: BEFORE_HASH,
        }))
      }],
      ['POST', '/v1/instances/ins_1/file-workspace/deletePath', () => {
        currentPath = ''
        return jsonResponse(mutationReceipt('deletePath', {
          sourcePath: renamedPath,
          preHash: BEFORE_HASH,
          postHash: null,
        }))
      }],
      ['GET', '/v1/instances/ins_1/file-workspace/listDirectory', () => jsonResponse(listing(
        currentPath
          ? [{ path: currentPath, name: currentPath, kind: 'file', size: 7, readOnly: false }]
          : [],
      ))],
    ])
    const files = new HttpFilesClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(
      files.rename('ins_1', PATH, { destinationPath: renamedPath, expectedRevision: BEFORE_HASH }),
    ).rejects.toMatchObject({ kind: 'validation', message: expect.stringContaining('must be read') })

    await files.read('ins_1', PATH)
    const renamed = await files.rename('ins_1', PATH, {
      destinationPath: renamedPath,
      expectedRevision: BEFORE_HASH,
    })
    expect(renamed.ok).toBe(true)
    if (!renamed.ok) return
    expect(renamed.entry.path).toBe(renamedPath)
    expect(fake.callsTo('/file-workspace/renamePath')[0].body).toEqual({
      sourcePath: PATH,
      destinationPath: renamedPath,
      expectedContentHash: BEFORE_HASH,
      expectedBaseSha: BASE_SHA,
    })

    const deleted = await files.delete('ins_1', renamedPath, { expectedRevision: BEFORE_HASH })
    expect(deleted.ok).toBe(true)
    if (!deleted.ok) return
    expect(deleted.receipt.id).toBe('file-deletePath-1')
    expect(fake.callsTo('/file-workspace/deletePath')[0].body).toEqual({
      path: renamedPath,
      expectedContentHash: BEFORE_HASH,
      expectedBaseSha: BASE_SHA,
    })
  })

  it.each([
    ['wrong rename destination', mutationReceipt('renamePath', {
      sourcePath: PATH,
      destinationPath: 'wrong.md',
      preHash: BEFORE_HASH,
      postHash: BEFORE_HASH,
    })],
    ['wrong delete revision', mutationReceipt('deletePath', {
      sourcePath: PATH,
      preHash: AFTER_HASH,
      postHash: null,
    })],
  ])('fails closed on %s receipt identity', async (label, receipt) => {
    const operation = label.startsWith('wrong rename') ? 'renamePath' : 'deletePath'
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/file-workspace/readFile', jsonResponse(read(PATH, 'before\n', BEFORE_HASH))],
      ['POST', `/v1/instances/ins_1/file-workspace/${operation}`, jsonResponse(receipt)],
    ])
    const files = new HttpFilesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await files.read('ins_1', PATH)
    const action =
      operation === 'renamePath'
        ? files.rename('ins_1', PATH, { destinationPath: 'RENAMED.md', expectedRevision: BEFORE_HASH })
        : files.delete('ins_1', PATH, { expectedRevision: BEFORE_HASH })
    await expect(action).rejects.toMatchObject({ kind: 'validation' })
  })

  it('returns a stale conflict without claiming a rename', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/file-workspace/readFile', jsonResponse(read(PATH, 'before\n', BEFORE_HASH))],
      ['POST', '/v1/instances/ins_1/file-workspace/renamePath', jsonResponse({
        ok: false,
        error: { code: 'file_workspace_refused', message: 'rename source changed' },
      }, 409)],
    ])
    const files = new HttpFilesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await files.read('ins_1', PATH)
    await expect(files.rename('ins_1', PATH, {
      destinationPath: 'RENAMED.md',
      expectedRevision: BEFORE_HASH,
    })).resolves.toEqual({
      ok: false,
      reason: 'conflict',
      detail: 'rename source changed',
    })
  })
})
