import { afterEach, expect, it, vi } from 'vitest'
import { copyText } from '../clipboard'

const clipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, 'clipboard')
const commandDescriptor = Object.getOwnPropertyDescriptor(document, 'execCommand')
afterEach(() => {
  if (clipboardDescriptor) Object.defineProperty(navigator, 'clipboard', clipboardDescriptor)
  else Reflect.deleteProperty(navigator, 'clipboard')
  if (commandDescriptor) Object.defineProperty(document, 'execCommand', commandDescriptor)
  else Reflect.deleteProperty(document, 'execCommand')
})

it.each([false, true, 'throw'])('reports clipboard fallback %s honestly and removes its temporary element', async (outcome) => {
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockRejectedValue(new Error('denied')) } })
  Object.defineProperty(document, 'execCommand', { configurable: true, value: () => {
    expect(document.querySelector('textarea')?.value).toBe('unsaved content')
    if (outcome === 'throw') throw new Error('unsupported')
    return outcome
  } })
  expect(await copyText('unsaved content')).toBe(outcome === true)
  expect(document.querySelector('textarea')).toBeNull()
})
