/**
 * detailActions — the bridge between palette commands and the open receipt
 * drawer. The drawer registers its verify handler while mounted; the
 * "Verify receipt integrity" command (registered by ReceiptsTool) invokes
 * it. Feature-local, not persisted.
 */
let verifyHandler: (() => void) | null = null

export function registerReceiptVerifyHandler(handler: (() => void) | null): void {
  verifyHandler = handler
}

export function requestReceiptVerify(): boolean {
  if (!verifyHandler) return false
  verifyHandler()
  return true
}
