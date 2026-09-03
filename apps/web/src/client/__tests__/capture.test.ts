import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { MockClient } from '../mock/adapter'
import { INSTANCE_IDS } from '../mock/seed'

const STUDY = INSTANCE_IDS.studyAlpha

function setCaptureQuery(enabled: boolean): void {
  window.history.replaceState(null, '', enabled ? '/?capture=studystate' : '/')
}

async function captureJourney() {
  const client = new MockClient()
  await client.scenario.resetMockState()
  const sent = await client.conversation.sendMessage(STUDY, { content: 'What should I focus on next?' })
  for await (const chunk of sent.stream) void chunk
  const instance = await client.applications.get(STUDY)
  const conversation = await client.conversation.get(STUDY)
  const exported = await client.conversation.exportConversation(STUDY)
  const receipts = await client.receipts.list({ instanceId: STUDY })
  return {
    packageState: instance.packageState,
    messages: conversation.messages,
    receiptIds: receipts.map((receipt) => receipt.id),
    receiptDigests: receipts.map((receipt) => receipt.payloadDigest),
    exportReceipt: { id: exported.receipt.id, digest: exported.receipt.payloadDigest },
  }
}

beforeEach(() => {
  window.localStorage.clear()
  setCaptureQuery(true)
})

afterEach(() => {
  window.localStorage.clear()
  setCaptureQuery(false)
})

describe('StudyState mock capture mode', () => {
  it('repeating reset/send produces identical state, messages, receipt ids, and digests', async () => {
    const first = await captureJourney()
    const second = await captureJourney()

    expect(second).toEqual(first)
    expect(first.messages.at(-2)).toMatchObject({
      id: 'msg_capture_study_user_0001',
      createdAt: '2026-08-01T12:00:00.000Z',
    })
    expect(first.messages.at(-1)).toMatchObject({
      id: 'msg_capture_study_assistant_0001',
      createdAt: '2026-08-01T12:00:00.000Z',
      state: 'complete',
    })
    expect(first.exportReceipt.id).toBe('rcpt_0011')
  })

  it('non-capture mock clients keep wall-clock receipt timestamps', async () => {
    setCaptureQuery(false)
    const client = new MockClient({ captureMode: false })
    await client.scenario.resetMockState()
    const firstReceipt = (await client.conversation.exportConversation(STUDY)).receipt
    await new Promise((resolve) => setTimeout(resolve, 5))
    const secondReceipt = (await client.conversation.exportConversation(STUDY)).receipt

    expect(secondReceipt.createdAt).not.toBe(firstReceipt.createdAt)
    expect(secondReceipt.createdAt).not.toBe('2026-08-01T12:00:00.000Z')
  })
})
