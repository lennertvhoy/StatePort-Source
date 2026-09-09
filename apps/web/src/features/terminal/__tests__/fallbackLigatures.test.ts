import { describe, expect, it, vi } from 'vitest'
import type { Terminal } from '@xterm/xterm'
import { FallbackLigatures, fallbackLigatureRanges } from '../fallbackLigatures'
import { FakeTerminal } from './fakeXterm'

describe('upstream deterministic fallback ligatures', () => {
  it('uses longest nonoverlapping ranges and UTF-16 positions without changing text', () => {
    const text = '😀 <====> !== ===> ->> plain'
    const ranges = fallbackLigatureRanges(text)
    expect(ranges).toEqual([[3, 9], [10, 13], [14, 18], [19, 22]])
    expect(ranges.map(([start, end]) => text.slice(start, end))).toEqual(['<====>', '!==', '===>', '->>'])
    expect(fallbackLigatureRanges('ordinary text 漢字')).toEqual([])
  })

  it('registers once, refreshes changes, explicitly disables font features and disposes', () => {
    const term = new FakeTerminal({})
    const register = vi.spyOn(term, 'registerCharacterJoiner')
    const deregister = vi.spyOn(term, 'deregisterCharacterJoiner')
    const refresh = vi.spyOn(term, 'refresh')
    const ligatures = new FallbackLigatures(term as unknown as Terminal)
    ligatures.setEnabled(false)
    expect(term.element.style.fontFeatureSettings).toBe('"calt" off, "liga" off')
    ligatures.setEnabled(true)
    ligatures.setEnabled(true)
    expect(register).toHaveBeenCalledTimes(1)
    expect(term.joiners.size).toBe(1)
    expect(term.element.style.fontFeatureSettings).toBe('"calt" on, "liga" on')
    expect(refresh).toHaveBeenCalledTimes(2)
    expect(term.written).toEqual([])
    ligatures.setEnabled(false)
    expect(deregister).toHaveBeenCalledTimes(1)
    expect(term.joiners.size).toBe(0)
    ligatures.setEnabled(true)
    ligatures.dispose()
    ligatures.dispose()
    expect(term.joiners.size).toBe(0)
    expect(term.element.style.fontFeatureSettings).toBe('"calt" off, "liga" off')
    expect(deregister).toHaveBeenCalledTimes(2)
  })
})
