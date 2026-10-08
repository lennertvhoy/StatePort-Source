/**
 * Conversation surface: seeded transcript, composer Enter/Shift+Enter, empty
 * send guard, draft persistence, streaming stop, scroll anchoring.
 */
import { expect, test, type Page } from '@playwright/test'

import { DESKTOP, INSTANCES, gotoApp, onProjects } from './helpers'

const CONVERSATION = `#/app/${INSTANCES.ctoPilot}/conversation`

async function transcriptScroller(page: Page) {
  const log = page.getByRole('log', { name: 'Conversation transcript' })
  await expect(log).toBeVisible()
  return log
}

test.describe('conversation', () => {
  onProjects(DESKTOP)

  test('seeded transcript renders with messages and tool events', async ({ page }) => {
    await gotoApp(page, CONVERSATION)
    const log = await transcriptScroller(page)
    await expect(log.getByRole('article')).toHaveCount(4)
    await expect(page.getByText('I added a short reminder line to notes/pilot-notes.md')).toBeVisible()
    await expect(page.getByTestId('thread-header')).toContainText('4 messages')
  })

  test('empty message cannot be sent (button disabled, Enter no-op)', async ({ page }) => {
    await gotoApp(page, CONVERSATION)
    await expect(page.getByTestId('composer-send')).toBeDisabled()
    await page.getByTestId('composer-input').click()
    await page.keyboard.press('Enter')
    await expect(page.getByRole('log', { name: 'Conversation transcript' }).getByRole('article')).toHaveCount(4)
  })

  test('Enter sends on desktop; Shift+Enter inserts a newline', async ({ page }) => {
    await gotoApp(page, CONVERSATION)
    const input = page.getByTestId('composer-input')

    await input.click()
    await page.keyboard.type('first line')
    await page.keyboard.press('Shift+Enter')
    await page.keyboard.type('second line')
    await expect(input).toHaveValue('first line\nsecond line')
    // Shift+Enter must not have sent anything.
    await expect(page.getByRole('log', { name: 'Conversation transcript' }).getByRole('article')).toHaveCount(4)

    await page.keyboard.press('Enter')
    // The user message lands and the composer clears.
    await expect(input).toHaveValue('')
    const log = page.getByRole('log', { name: 'Conversation transcript' })
    await expect(log.getByRole('article').first()).toContainText('Can you summarize')
    await expect(page.getByRole('article', { name: 'Your message' }).last()).toContainText('first line\nsecond line')
  })

  test('draft survives a route change', async ({ page }) => {
    await gotoApp(page, CONVERSATION)
    const input = page.getByTestId('composer-input')
    await input.click()
    await page.keyboard.type('draft kept across navigation')

    await page.getByTestId('app-context-shell').getByRole('link', { name: 'Overview' }).click()
    await expect(page.getByTestId('app-overview-page')).toBeVisible()

    await page.getByTestId('app-context-shell').getByRole('link', { name: 'Conversation' }).click()
    await expect(page.getByTestId('composer-input')).toHaveValue('draft kept across navigation')
  })

  test('streaming response can be stopped', async ({ page }) => {
    // conversation_streaming slows the mock stream to 1 word / 220 ms, so the
    // in-flight window is deterministic. (The scenario also seeds an in-flight
    // reply that the surface resumes on load with its own stop control; this
    // test drives a fresh in-session stream on top of it.)
    await gotoApp(page, CONVERSATION, 'conversation_streaming')
    const input = page.getByTestId('composer-input')
    await input.click()
    await page.keyboard.type('stream a long reply please')
    await page.keyboard.press('Enter')

    const stop = page.getByTestId('stop-stream')
    await expect(stop).toBeVisible()
    await expect(page.getByTestId('streaming-indicator')).toBeVisible()
    await stop.click()
    await expect(page.getByTestId('streaming-indicator')).not.toBeVisible()
    await expect(page.getByText('Stopped by you').first()).toBeVisible()
  })

  test('no scroll-yank while reading older messages', async ({ page }) => {
    await gotoApp(page, CONVERSATION)
    const log = await transcriptScroller(page)

    // Scroll to the very top (older messages) and hold.
    await log.evaluate((el) => {
      el.scrollTop = 0
    })
    await page.waitForTimeout(400)
    const top1 = await log.evaluate((el) => el.scrollTop)
    await page.waitForTimeout(1200)
    const top2 = await log.evaluate((el) => el.scrollTop)
    expect(top2, `scroll position moved ${top1} → ${top2} without user input`).toBe(top1)
  })

  test('streaming does not yank the reader back to the bottom', async ({ page }) => {
    await gotoApp(page, CONVERSATION, 'conversation_streaming')
    const log = await transcriptScroller(page)
    // Start a live stream (slowed by the scenario) so content keeps arriving.
    await page.getByTestId('composer-input').click()
    await page.keyboard.type('stream a long reply please')
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('streaming-indicator')).toBeVisible()

    // The user scrolls up to read older messages — position must hold.
    // (A real wheel gesture, not a programmatic scrollTop write: the pause
    // flag is driven by the scroll event, so simulate the actual input.)
    await log.hover()
    await page.mouse.wheel(0, -4000)
    await expect
      .poll(async () => log.evaluate((el) => el.scrollTop), { timeout: 5000 })
      .toBeLessThan(5)
    await page.waitForTimeout(1000) // several stream chunks arrive meanwhile
    const top = await log.evaluate((el) => el.scrollTop)
    expect(top, `reader was yanked to scrollTop=${top} during streaming`).toBeLessThan(5)
    // The "jump to latest" affordance appears instead of a forced scroll.
    await expect(page.getByTestId('jump-to-latest')).toBeVisible()
    // Clean up: stop the stream.
    await page.getByTestId('stop-stream').click()
    await expect(page.getByTestId('streaming-indicator')).not.toBeVisible()
  })
})
