/**
 * The analyses submitted from this browser by the signed-in account.
 *
 * The agents service answers for one task at a time and lists none, so the
 * page that shows "my analyses" has to remember which it submitted. They are
 * kept in localStorage, as the playbook runs are (use-execution-status.ts),
 * under a key of the account's own: a second account using the same browser
 * does not see the first one's indicators. Only the task id and the
 * indicator are kept; the status and the report are always the service's.
 */
import { useCallback, useMemo, useSyncExternalStore } from 'react'
import { IOC_TYPES, type Ioc } from '@/lib/agents-api'

export interface SubmittedAnalysis {
  task_id: string
  ioc: Ioc
  submitted_at: string
}

const KEY_PREFIX = 'wildbox_ai_analyses:'
/** The service keeps a task for an hour; a longer list would be of expired ones. */
const MAX_ITEMS = 20

const listeners = new Set<() => void>()
/* What was written when localStorage refused (private browsing, storage
   disabled): the list still works for the life of the page. */
const memory = new Map<string, string>()

function subscribe(onChange: () => void) {
  listeners.add(onChange)
  window.addEventListener('storage', onChange)
  return () => {
    listeners.delete(onChange)
    window.removeEventListener('storage', onChange)
  }
}

function read(key: string): string | null {
  try {
    return localStorage.getItem(key) ?? memory.get(key) ?? null
  } catch {
    return memory.get(key) ?? null
  }
}

function write(key: string, items: SubmittedAnalysis[]) {
  const raw = JSON.stringify(items)
  memory.set(key, raw)
  try {
    localStorage.setItem(key, raw)
  } catch {
    // Kept in memory, above.
  }
  listeners.forEach(notify => notify())
}

function isSubmitted(item: unknown): item is SubmittedAnalysis {
  const candidate = item as Partial<SubmittedAnalysis> | null
  return (
    !!candidate &&
    typeof candidate.task_id === 'string' &&
    typeof candidate.submitted_at === 'string' &&
    typeof candidate.ioc?.value === 'string' &&
    IOC_TYPES.includes(candidate.ioc.type)
  )
}

/** The stored list; anything in it that is not a submission is dropped. */
function parse(raw: string | null): SubmittedAnalysis[] {
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter(isSubmitted) : []
  } catch {
    return []
  }
}

export function useSubmittedAnalyses(userId: string | undefined) {
  const key = userId ? `${KEY_PREFIX}${userId}` : null
  const raw = useSyncExternalStore(
    subscribe,
    () => (key ? read(key) : null),
    () => null
  )
  const items = useMemo(() => parse(raw), [raw])

  const add = useCallback(
    (item: SubmittedAnalysis) => {
      if (key) write(key, [item, ...parse(read(key))].slice(0, MAX_ITEMS))
    },
    [key]
  )
  const remove = useCallback(
    (taskId: string) => {
      if (key)
        write(
          key,
          parse(read(key)).filter(item => item.task_id !== taskId)
        )
    },
    [key]
  )

  return { items, add, remove }
}
