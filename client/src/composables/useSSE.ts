import { onUnmounted } from 'vue'
import { apiKey } from '../auth'

export type SSEEvent = 'users' | 'groups' | 'flows' | 'sessions'
type Handler = () => void

// One connection shared across all components for the lifetime of the page.
const subscribers = new Map<SSEEvent, Set<Handler>>()
let es: EventSource | null = null

const ALL_EVENTS: SSEEvent[] = ['users', 'groups', 'flows', 'sessions']

function openIfNeeded() {
  if (!apiKey) return
  if (es && es.readyState !== EventSource.CLOSED) return
  es = new EventSource(`/api/v1/events?api_key=${encodeURIComponent(apiKey)}`)
  for (const event of ALL_EVENTS) {
    es.addEventListener(event, () => subscribers.get(event)?.forEach(h => h()))
  }
}

export function useSSE(handlers: Partial<Record<SSEEvent, Handler>>): void {
  for (const [event, handler] of Object.entries(handlers) as [SSEEvent, Handler][]) {
    if (!subscribers.has(event)) subscribers.set(event, new Set())
    subscribers.get(event)!.add(handler)
  }

  openIfNeeded()

  onUnmounted(() => {
    for (const [event, handler] of Object.entries(handlers) as [SSEEvent, Handler][]) {
      subscribers.get(event)?.delete(handler)
    }
    if ([...subscribers.values()].every(s => s.size === 0)) {
      es?.close()
      es = null
    }
  })
}
