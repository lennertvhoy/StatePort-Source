/**
 * Paste guard — multiline detection, destructive-pattern detection, and the
 * confirmation policy (setting-gated for multiline, unconditional for risk).
 */
import { describe, expect, it } from 'vitest'

import { analyzePaste, highlightLine, pasteNeedsConfirmation } from '../pasteGuard'

describe('analyzePaste', () => {
  it('treats a single line as a simple paste', () => {
    const a = analyzePaste('git status')
    expect(a.multiline).toBe(false)
    expect(a.lineCount).toBe(1)
    expect(a.destructive).toBe(false)
  })

  it('counts lines without inventing a trailing phantom line', () => {
    const a = analyzePaste('ls\ncat README.md\n')
    expect(a.lineCount).toBe(2)
    expect(a.multiline).toBe(true)
    expect(a.lines).toEqual(['ls', 'cat README.md'])
  })

  it('normalizes CRLF before counting', () => {
    const a = analyzePaste('ls\r\npwd')
    expect(a.lineCount).toBe(2)
    expect(a.lines).toEqual(['ls', 'pwd'])
  })

  it('flags rm -rf as destructive', () => {
    const a = analyzePaste('rm -rf /tmp/build')
    expect(a.destructive).toBe(true)
    expect(a.risks.map((r) => r.id)).toContain('rm-recursive-force')
  })

  it('flags each required destructive pattern', () => {
    expect(analyzePaste('dd if=/dev/zero of=/dev/sda').risks.map((r) => r.id)).toEqual(
      expect.arrayContaining(['dd', 'raw-device']),
    )
    expect(analyzePaste('mkfs.ext4 /dev/sda1').destructive).toBe(true)
    expect(analyzePaste('shutdown -h now').risks.map((r) => r.id)).toContain('shutdown')
    expect(analyzePaste(':(){ :|:& };:').risks.map((r) => r.id)).toContain('fork-bomb')
    expect(analyzePaste('echo ok > /dev/sdb').risks.map((r) => r.id)).toContain('raw-device')
    expect(analyzePaste('sudo nixos-rebuild switch').risks.map((r) => r.id)).toContain('sudo')
  })

  it('does not flag everyday commands', () => {
    for (const cmd of ['git status', 'ls -la', 'cat README.md', 'nix flake check', 'rm build.log']) {
      expect(analyzePaste(cmd).destructive, cmd).toBe(false)
    }
  })
})

describe('pasteNeedsConfirmation', () => {
  it('confirms multiline pastes only when the setting is on', () => {
    const a = analyzePaste('ls\npwd')
    expect(pasteNeedsConfirmation(a, true)).toBe(true)
    expect(pasteNeedsConfirmation(a, false)).toBe(false)
  })

  it('always confirms destructive pastes, whatever the setting', () => {
    const a = analyzePaste('rm -rf /')
    expect(pasteNeedsConfirmation(a, true)).toBe(true)
    expect(pasteNeedsConfirmation(a, false)).toBe(true)
  })

  it('never confirms a harmless single line', () => {
    const a = analyzePaste('git status')
    expect(pasteNeedsConfirmation(a, true)).toBe(false)
  })
})

describe('highlightLine', () => {
  it('marks risky segments for the preview', () => {
    const segments = highlightLine('sudo rm -rf /var', analyzePaste('sudo rm -rf /var').risks)
    const riskyText = segments.filter((s) => s.risky).map((s) => s.text)
    expect(riskyText).toContain('sudo')
    expect(riskyText.some((t) => t.includes('rm -rf'))).toBe(true)
  })

  it('returns the whole line unflagged when no risk matches', () => {
    expect(highlightLine('ls -la', [])).toEqual([{ text: 'ls -la', risky: false }])
  })
})
