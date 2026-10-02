/**
 * Cross-client freshness: a change made by another tab/browser never reaches this page, so the
 * shell's instance projection must not be trusted forever. Found by the concurrent-clients e2e row
 * (the browser that lost an approve race kept showing "Not started" after navigating away and back;
 * only a hard reload fixed it).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ApplicationInstance } from '@/client'
import { getClient, resetClientForTests } from '@/client'

import { INSTANCE_CACHE_MAX_AGE_MS, fetchInstanceCached, invalidateInstanceCache } from '../data'

const ID = 'ins_00aa11bb22cc33dd'

function instance(name: string): ApplicationInstance {
  return { id: ID, name } as unknown as ApplicationInstance
}

beforeEach(() => {
  vi.useFakeTimers()
  resetClientForTests()
  invalidateInstanceCache()
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
  resetClientForTests()
  invalidateInstanceCache()
})

describe('shell instance cache freshness', () => {
  it('serves the cache inside the max age and re-reads the service after it', async () => {
    let served = 'before'
    const get = vi.spyOn(getClient().applications, 'get').mockImplementation(async () => instance(served))

    expect((await fetchInstanceCached(ID)).name).toBe('before')
    served = 'changed by another client'

    vi.advanceTimersByTime(INSTANCE_CACHE_MAX_AGE_MS - 1)
    expect((await fetchInstanceCached(ID)).name).toBe('before')
    expect(get).toHaveBeenCalledTimes(1)

    vi.advanceTimersByTime(2)
    expect((await fetchInstanceCached(ID)).name).toBe('changed by another client')
    expect(get).toHaveBeenCalledTimes(2)
  })

  it('falls back to the aged copy when the refresh fails', async () => {
    const get = vi.spyOn(getClient().applications, 'get').mockResolvedValueOnce(instance('kept'))
    expect((await fetchInstanceCached(ID)).name).toBe('kept')
    get.mockRejectedValueOnce(new Error('service restarting'))
    vi.advanceTimersByTime(INSTANCE_CACHE_MAX_AGE_MS + 1)
    expect((await fetchInstanceCached(ID)).name).toBe('kept')
  })
})
