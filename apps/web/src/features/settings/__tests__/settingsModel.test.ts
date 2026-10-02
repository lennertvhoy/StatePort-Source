import { describe, expect, it } from 'vitest'

import { scenarioToolsAvailable } from '../model'

describe('settings production boundaries', () => {
  it('limits Scenario Lab and mock-data mutations to development mock builds', () => {
    expect(scenarioToolsAvailable('mock', 'development')).toBe(true)
    expect(scenarioToolsAvailable('http', 'development')).toBe(false)
    expect(scenarioToolsAvailable('mock', 'production')).toBe(false)
    expect(scenarioToolsAvailable('http', 'production')).toBe(false)
  })
})
