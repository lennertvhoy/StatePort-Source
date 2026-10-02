import { describe, expect, it } from 'vitest'

import { MockClient } from '../mock/adapter'
import { INSTANCE_IDS } from '../mock/seed'

const NIXOS = INSTANCE_IDS.nixosInfra

describe('governed file-write flow', () => {
  it('write with the expected revision produces a FileChange + Receipt', async () => {
    const client = new MockClient()
    const entry = await client.files.read(NIXOS, 'flake.nix')
    expect(entry.revision).toMatch(/^rev_/)

    const updated = entry.content.replace('personal infrastructure flake', 'personal homelab flake')
    const result = await client.files.write(NIXOS, 'flake.nix', {
      content: updated,
      expectedRevision: entry.revision,
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.change.beforeRevision).toBe(entry.revision)
    expect(result.change.afterRevision).not.toBe(entry.revision)
    expect(result.change.diff.unified).toContain('--- a/flake.nix')
    expect(result.receipt.actionName).toBe('File change saved')
    expect(result.receipt.expectedRevision).toBe(entry.revision)
    expect(result.receipt.resultRevision).toBe(result.change.afterRevision)
    expect(result.entry.content).toBe(updated)

    // The receipt is queryable and verifiable.
    const receipt = await client.receipts.get(result.receipt.id)
    expect(receipt.eventKind).toBe('file.write')
    const verification = await client.receipts.verify(receipt.id)
    expect(verification.ok).toBe(true)
  })

  it('write with a stale revision is a conflict, not an overwrite', async () => {
    const client = new MockClient()
    const first = await client.files.read(NIXOS, 'README.md')
    await client.files.write(NIXOS, 'README.md', {
      content: `${first.content}\nNew line.\n`,
      expectedRevision: first.revision,
    })
    const stale = await client.files.write(NIXOS, 'README.md', {
      content: 'clobbered',
      expectedRevision: first.revision,
    })
    expect(stale.ok).toBe(false)
    if (stale.ok) return
    expect(stale.reason).toBe('conflict')
    expect(stale.currentRevision).toBeDefined()
    expect(stale.currentContent).toContain('New line.')
  })

  it('rejects paths outside the project root (path policy)', async () => {
    const client = new MockClient()
    const result = await client.files.write(NIXOS, '../secrets.env', {
      content: 'x',
      expectedRevision: 'rev_anything',
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('path_policy')
  })

  it('refuses to write read-only files', async () => {
    const client = new MockClient()
    const entry = await client.files.read(NIXOS, 'hosts/homelab/hardware-configuration.nix')
    expect(entry.readOnly).toBe(true)
    const result = await client.files.write(NIXOS, entry.path, {
      content: '{}',
      expectedRevision: entry.revision,
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('read_only')
  })

  it('creates, renames, and deletes a regular file through reviewed bases', async () => {
    const client = new MockClient()
    await client.files.listTree(NIXOS)

    const created = await client.files.create(NIXOS, 'notes/reviewed.md', {
      content: '# Reviewed\n',
    })
    expect(created.ok).toBe(true)
    if (!created.ok) return
    expect(created.receipt.eventKind).toBe('file.create')
    expect(created.entry.content).toBe('# Reviewed\n')

    const renamed = await client.files.rename(NIXOS, created.path, {
      destinationPath: 'notes/accepted.md',
      expectedRevision: created.entry.revision,
    })
    expect(renamed.ok).toBe(true)
    if (!renamed.ok) return
    expect(renamed.receipt.eventKind).toBe('file.rename')
    await expect(client.files.read(NIXOS, created.path)).rejects.toMatchObject({ status: 404 })

    const deleted = await client.files.delete(NIXOS, renamed.destinationPath, {
      expectedRevision: renamed.entry.revision,
    })
    expect(deleted.ok).toBe(true)
    if (!deleted.ok) return
    expect(deleted.receipt.eventKind).toBe('file.delete')
    await expect(client.files.read(NIXOS, renamed.destinationPath)).rejects.toMatchObject({ status: 404 })
  })

  it('does not rename from a stale read or delete a read-only file', async () => {
    const client = new MockClient()
    const first = await client.files.read(NIXOS, 'README.md')
    const external = await client.files.write(NIXOS, 'README.md', {
      content: `${first.content}\nExternal.\n`,
      expectedRevision: first.revision,
    })
    expect(external.ok).toBe(true)
    const stale = await client.files.rename(NIXOS, 'README.md', {
      destinationPath: 'README-renamed.md',
      expectedRevision: first.revision,
    })
    expect(stale).toMatchObject({ ok: false, reason: 'conflict' })

    const readOnly = await client.files.read(NIXOS, 'hosts/homelab/hardware-configuration.nix')
    const refused = await client.files.delete(NIXOS, readOnly.path, {
      expectedRevision: readOnly.revision,
    })
    expect(refused).toMatchObject({ ok: false, reason: 'read_only' })
  })
})
