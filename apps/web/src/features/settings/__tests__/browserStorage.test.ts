import { beforeEach, describe, expect, it } from 'vitest'

import {
  STATEPORT_BROWSER_STORAGE_CATEGORIES,
  clearStatePortBrowserStorage,
  inspectStatePortBrowserStorage,
} from '../browserStorage'

beforeEach(() => {
  window.localStorage.clear()
  window.sessionStorage.clear()
})

describe('StatePort browser-storage boundary', () => {
  it('inventories key names only across persistent and per-tab storage', () => {
    window.localStorage.setItem('stateport.workspace.v1', '{"drafts":{"conv":"private text"}}')
    window.localStorage.setItem('unrelated.app', 'keep')
    window.sessionStorage.setItem(
      'stateport.terminal.tabs.v1',
      '{"instance":{"tabs":[{"sessionId":"pty-1"}]}}',
    )

    expect(inspectStatePortBrowserStorage()).toEqual({
      local: {
        available: true,
        keys: ['stateport.workspace.v1'],
      },
      session: {
        available: true,
        keys: ['stateport.terminal.tabs.v1'],
      },
      totalKeys: 2,
    })
  })

  it('clears every current or future StatePort-prefixed key and preserves unrelated origin data', () => {
    window.localStorage.setItem('stateport.workspace.v1', 'workspace')
    window.localStorage.setItem('stateport.future-feature.v9', 'future')
    window.localStorage.setItem('stateport_session', 'not-a-StatePort-Web-Storage-key')
    window.localStorage.setItem('another.product.v1', 'preserve')
    window.sessionStorage.setItem('stateport.terminal.tabs.v1', 'markers only')
    window.sessionStorage.setItem('stateport.future-session.v1', 'future')
    window.sessionStorage.setItem('another.session', 'preserve')

    const result = clearStatePortBrowserStorage()

    expect(result.removedLocalKeys).toEqual([
      'stateport.future-feature.v9',
      'stateport.workspace.v1',
    ])
    expect(result.removedSessionKeys).toEqual([
      'stateport.future-session.v1',
      'stateport.terminal.tabs.v1',
    ])
    expect(result.remaining.totalKeys).toBe(0)
    expect(window.localStorage.getItem('another.product.v1')).toBe('preserve')
    expect(window.localStorage.getItem('stateport_session')).toBe(
      'not-a-StatePort-Web-Storage-key',
    )
    expect(window.sessionStorage.getItem('another.session')).toBe('preserve')
  })

  it('documents every currently audited key without listing credentials or terminal output', () => {
    const keys = STATEPORT_BROWSER_STORAGE_CATEGORIES.map((item) => item.key)
    expect(keys).toEqual([
      'stateport.workspace.v1',
      'stateport.applications.v1',
      'stateport.conversation.v1',
      'stateport.receipts-ui.v1',
      'stateport.commands.v1',
      'stateport.shortcuts.v1',
      'stateport.http.ui-overlay.v1',
      'stateport.http.global-ui-settings.v1',
      'stateport.http.app-ui-settings.v1',
      'stateport.orchestration.how-it-works.dismissed',
      'stateport.mock.v1',
      'stateport.terminal.tabs.v1',
    ])
    expect(
      STATEPORT_BROWSER_STORAGE_CATEGORIES.some((item) =>
        /credential|provider token/i.test(item.contents),
      ),
    ).toBe(false)
    expect(
      STATEPORT_BROWSER_STORAGE_CATEGORIES.find(
        (item) => item.key === 'stateport.terminal.tabs.v1',
      )?.contents,
    ).toContain('Terminal output is never stored')
  })
})
