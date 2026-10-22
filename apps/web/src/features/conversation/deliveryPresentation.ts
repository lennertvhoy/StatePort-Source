import type { Conversation, ConversationChannel } from '@/client'

type Presentation = { state: 'success' | 'neutral' | 'attention' | 'danger'; label: string }

/** Delivery facts do not attest channel connectivity. Absence is not configuration. */
export function deliveryPresentation(state?: Conversation['deliveryState']): Presentation {
  switch (state) {
    case 'delivered': return { state: 'success', label: 'Delivered' }
    case 'pending': return { state: 'attention', label: 'Pending' }
    case 'failed': return { state: 'danger', label: 'Delivery failed' }
    case 'not_configured': return { state: 'neutral', label: 'Not configured' }
    default: return { state: 'neutral', label: 'Delivery status unavailable' }
  }
}

export function channelName(channel: ConversationChannel | undefined): string {
  return channel === 'telegram' ? 'Telegram' : 'Web'
}

export function conversationDeliveryPresentation(conversation: Conversation | null): Presentation {
  const presentation = deliveryPresentation(conversation?.deliveryState)
  if (!conversation) return presentation
  // A conversation always has a channel; with no delivery fact the header names the channel and claims nothing more.
  if (conversation.deliveryState === 'unknown' || conversation.deliveryState === undefined) {
    return { state: 'neutral', label: channelName(conversation.channel) }
  }
  return { ...presentation, label: `${channelName(conversation.channel)} · ${presentation.label}` }
}

/** The typed projection provides delivery facts only for this conversation's channel. */
export function channelDeliveryPresentation(conversation: Conversation | null, channel: ConversationChannel): Presentation {
  if (!conversation || conversation.channel !== channel || conversation.deliveryState === 'unknown') {
    return { state: 'neutral', label: 'Status unavailable' }
  }
  const presentation = deliveryPresentation(conversation.deliveryState)
  return { ...presentation, label: `Delivery · ${presentation.label}` }
}
