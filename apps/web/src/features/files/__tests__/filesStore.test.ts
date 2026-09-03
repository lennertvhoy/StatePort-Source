/**
 * filesStore unit tests — document lifecycle, dirty tracking, read-only
 * protection, and tree helpers, against the real mock client.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getClient, resetMockState } from '@/client'
import type { FileNode } from '@/client'

import {
  ancestorDirs,
  dirtyPathsOf,
  docIsDirty,
  flattenFilePaths,
  useFilesStore,
} from '../filesStore'

const ID = 'ins_nixos_infra'

beforeEach(() => {
  localStorage.clear()
  resetMockState()
  useFilesStore.getState().resetForTests()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('filesStore documents', () => {
  it('loads a document with its revision (the expectedRevision source)', async () => {
    const doc = await useFilesStore.getState().openDocument(ID, 'flake.nix')
    expect(doc?.status).toBe('ready')
    expect(doc?.revision).toMatch(/^rev_/)
    expect(doc?.savedContent.length).toBeGreaterThan(0)
    expect(docIsDirty(doc!)).toBe(false)
  }, 10_000)

  it('marks a document dirty on edit and clean again on discard', async () => {
    await useFilesStore.getState().openDocument(ID, 'flake.nix')
    useFilesStore.getState().setDraft(ID, 'flake.nix', '# edited\n')
    let doc = useFilesStore.getState().docs[ID]!['flake.nix']!
    expect(docIsDirty(doc)).toBe(true)
    expect(dirtyPathsOf(useFilesStore.getState().docs[ID])).toEqual(['flake.nix'])
    useFilesStore.getState().discardDraft(ID, 'flake.nix')
    doc = useFilesStore.getState().docs[ID]!['flake.nix']!
    expect(docIsDirty(doc)).toBe(false)
  }, 10_000)

  it('never edits a read-only document', async () => {
    const doc = await useFilesStore.getState().openDocument(ID, 'hosts/homelab/hardware-configuration.nix')
    expect(doc?.readOnly).toBe(true)
    useFilesStore.getState().setDraft(ID, 'hosts/homelab/hardware-configuration.nix', 'changed')
    const after = useFilesStore.getState().docs[ID]!['hosts/homelab/hardware-configuration.nix']!
    expect(after.draft).toBe(after.savedContent)
    expect(docIsDirty(after)).toBe(false)
  }, 10_000)

  it('applyEntry records saved content, new revision, and the receipt', async () => {
    await useFilesStore.getState().openDocument(ID, 'flake.nix')
    useFilesStore.getState().setDraft(ID, 'flake.nix', '# new content\n')
    const revision = useFilesStore.getState().docs[ID]!['flake.nix']!.revision
    const result = await getClient().files.write(ID, 'flake.nix', {
      content: '# new content\n',
      expectedRevision: revision,
    })
    expect(result.ok).toBe(true)
    if (result.ok) {
      useFilesStore.getState().applyEntry(ID, 'flake.nix', result.entry, result.receipt.id)
      const doc = useFilesStore.getState().docs[ID]!['flake.nix']!
      expect(docIsDirty(doc)).toBe(false)
      expect(doc.savedContent).toBe('# new content\n')
      expect(doc.revision).toBe(result.entry.revision)
      expect(doc.lastReceiptId).toBe(result.receipt.id)
    }
  }, 10_000)

  it('reloadDocument never clobbers an in-flight dirty draft', async () => {
    await useFilesStore.getState().openDocument(ID, 'README.md')
    useFilesStore.getState().setDraft(ID, 'README.md', 'conflicting edit')
    const reloaded = await useFilesStore.getState().reloadDocument(ID, 'README.md')
    expect(reloaded?.draft).toBe('conflicting edit')
    expect(docIsDirty(reloaded!)).toBe(true)
  }, 10_000)
})

describe('tree helpers', () => {
  it('does not let an invalidated tree read overwrite a fresh tree', async () => {
    const staleNodes: FileNode[] = [{ kind: 'file', name: 'stale.md', path: 'stale.md' }]
    const freshNodes: FileNode[] = [{ kind: 'file', name: 'fresh.md', path: 'fresh.md' }]
    let resolveStale!: (nodes: FileNode[]) => void
    const staleRead = new Promise<FileNode[]>((resolve) => {
      resolveStale = resolve
    })
    vi.spyOn(getClient().files, 'listTree').mockReturnValueOnce(staleRead).mockResolvedValueOnce(freshNodes)

    const oldRequest = useFilesStore.getState().loadTree(ID)
    await Promise.resolve()
    useFilesStore.getState().resetForTests()
    const freshRequest = useFilesStore.getState().loadTree(ID)
    await freshRequest
    resolveStale(staleNodes)
    await oldRequest

    expect(useFilesStore.getState().trees[ID]?.nodes).toEqual(freshNodes)
  })

  it('makes a forced refresh authoritative over an older pending read', async () => {
    const staleNodes: FileNode[] = [{ kind: 'file', name: 'stale.md', path: 'stale.md' }]
    const freshNodes: FileNode[] = [{ kind: 'file', name: 'fresh.md', path: 'fresh.md' }]
    let resolveStale!: (nodes: FileNode[]) => void
    const staleRead = new Promise<FileNode[]>((resolve) => {
      resolveStale = resolve
    })
    const listTree = vi.spyOn(getClient().files, 'listTree')
      .mockReturnValueOnce(staleRead)
      .mockResolvedValueOnce(freshNodes)

    const oldRequest = useFilesStore.getState().loadTree(ID)
    await Promise.resolve()
    const freshRequest = useFilesStore.getState().loadTree(ID, { force: true })
    await freshRequest
    resolveStale(staleNodes)
    await oldRequest

    expect(listTree).toHaveBeenCalledTimes(2)
    expect(useFilesStore.getState().trees[ID]?.nodes).toEqual(freshNodes)
  })

  it('flattens file paths depth-first', () => {
    const paths = flattenFilePaths([
      {
        kind: 'directory',
        name: 'hosts',
        path: 'hosts',
        children: [
          { kind: 'file', name: 'a.nix', path: 'hosts/a.nix' },
          { kind: 'file', name: 'b.nix', path: 'hosts/b.nix' },
        ],
      },
      { kind: 'file', name: 'flake.nix', path: 'flake.nix' },
    ])
    expect(paths).toEqual(['hosts/a.nix', 'hosts/b.nix', 'flake.nix'])
  })

  it('computes ancestor directories', () => {
    expect(ancestorDirs('hosts/homelab/configuration.nix')).toEqual(['hosts', 'hosts/homelab'])
    expect(ancestorDirs('flake.nix')).toEqual([])
  })
})
