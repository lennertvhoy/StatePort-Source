/*!
 * @license MIT
 * Copyright (c) 2017-2019, The xterm.js authors (https://github.com/xtermjs/xterm.js)
 * Copyright (c) 2014-2016, SourceLair Private Company (https://www.sourcelair.com)
 * Copyright (c) 2012-2013, Christopher Jeffrey (https://github.com/chjj/)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/**
 * Deterministic browser fallback from @xterm/addon-ligatures 0.10.0,
 * xterm.js tag 6.0.0, src/LigaturesAddon.ts and src/index.ts.
 * https://github.com/xtermjs/xterm.js/tree/6.0.0/addons/addon-ligatures/src
 * Copyright (c) 2018 The xterm.js authors. MIT; see xterm-ligatures.LICENSE.
 *
 * The upstream ranges and longest-first matching algorithm are unchanged.
 * Adaptation: no font discovery/parser/cache; explicit disable and refresh.
 * These are common programming sequences, not a complete font shaping engine.
 * The selected font still determines whether a joined sequence has a ligature.
 */
import type { Terminal } from '@xterm/xterm'

const FALLBACK_LIGATURES = [
  '<--', '<---', '<<-', '<-', '->', '->>', '-->', '--->',
  '<==', '<===', '<<=', '<=', '=>', '=>>', '==>', '===>', '>=', '>>=',
  '<->', '<-->', '<--->', '<---->', '<=>', '<==>', '<===>', '<====>', '::', ':::',
  '<~~', '</', '</>', '/>', '~~>', '==', '!=', '/=', '~=', '<>', '===', '!==', '!===',
  '<:', ':=', '*=', '*+', '<*', '<*>', '*>', '<|', '<|>', '|>', '+*', '=*', '=:', ':>',
  '/*', '*/', '+++', '<!--', '<!---',
].sort((a, b) => b.length - a.length)

export function fallbackLigatureRanges(text: string): [number, number][] {
  const ranges: [number, number][] = []
  for (let i = 0; i < text.length; i++) {
    for (let j = 0; j < FALLBACK_LIGATURES.length; j++) {
      if (text.startsWith(FALLBACK_LIGATURES[j], i)) {
        ranges.push([i, i + FALLBACK_LIGATURES[j].length])
        i += FALLBACK_LIGATURES[j].length - 1
        break
      }
    }
  }
  return ranges
}

/** One joiner per live xterm, including detach/reattach and preference changes. */
export class FallbackLigatures {
  private joinerId: number | undefined
  private enabled: boolean | undefined

  private readonly terminal: Terminal

  constructor(terminal: Terminal) { this.terminal = terminal }

  setEnabled(enabled: boolean): void {
    if (enabled === this.enabled) return
    if (enabled) {
      this.joinerId = this.terminal.registerCharacterJoiner(fallbackLigatureRanges)
    } else if (this.joinerId !== undefined) {
      this.terminal.deregisterCharacterJoiner(this.joinerId)
      this.joinerId = undefined
    }
    this.enabled = enabled
    if (this.terminal.element) {
      // Explicit off also covers spans the DOM renderer merges on its own.
      this.terminal.element.style.fontFeatureSettings = enabled
        ? '"calt" on, "liga" on'
        : '"calt" off, "liga" off'
    }
    this.terminal.refresh(0, this.terminal.rows - 1)
  }

  dispose(): void {
    this.setEnabled(false)
  }
}
