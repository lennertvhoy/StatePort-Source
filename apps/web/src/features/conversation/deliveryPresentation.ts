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

export function conversationDeliveryPresentation(conversation: Conversation | null): Presentation {
  const presentation = deliveryPresentation(conversation?.deliveryState)
  if (!conversation || conversation.deliveryState === 'unknown') return presentation
  const channel = conversation.channel === 'telegram' ? 'Telegram' : 'Web'
  return { ...presentation, label: `${channel} · ${presentation.label}` }
}

/** The typed projection provides delivery facts only for this conversation's channel. */
export function channelDeliveryPresentation(conversation: Conversation | null, channel: ConversationChannel): Presentation {
  if (!conversation || conversation.channel !== channel || conversation.deliveryState === 'unknown') {
    return { state: 'neutral', label: 'Status unavailable' }
  }
  const presentation = deliveryPresentation(conversation.deliveryState)
  return { ...presentation, label: `Delivery · ${presentation.label}` }
}
