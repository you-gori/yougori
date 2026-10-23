/** One event stream for every grid, and the shared read behind it.
 *
 *  The mechanism is the one this repository already uses: a desktop event, listened to exactly
 *  as `marketApi.listen` does for `yougori-market`. Nothing new is opened. A hub serves member
 *  computers over its own HTTPS port with its own sign-in, and pointing the window at one of
 *  those would be a second listening port and a second sign-in for no new capability.
 *
 *  An event is an accelerator, never the truth. Three things make that necessary rather than
 *  tidy: the command line talks the local wire and cannot receive a desktop event at all, the
 *  browser fixture has no desktop app, and no product emits this event yet. So every watcher is
 *  served by the shared read on a timer, and an event, when one arrives, only brings the next
 *  read forward. Behaviour on the day this lands is exactly today's behaviour.
 *
 *  The name is `yougori-grids-news`. Not `yougori-grid`: the keychain already holds
 *  `yougori-grid-hub-key`, `yougori-grid-hub-password` and `yougori-grid-member-token`, and an
 *  event that reads like a vault entry is a trap for whoever greps next.
 */
import type { ApprovalState, ModelProgress, RealmLifecycle, WorkspaceState } from "@/api/grids/types"

export const GRID_EVENT = "yougori-grids-news"

interface Notice {
  realmId: string
  /** Per grid, rising. A gap means a watcher missed one and should read again. */
  seq: number
  at: number
  /** The call that caused it, when the engine knows which one. */
  requestId?: string
}

export type GridEvent =
  | (Notice & { kind: "realmChanged"; lifecycle: RealmLifecycle })
  | (Notice & { kind: "hostChanged"; hostId: string; online: boolean; excluded: boolean })
  | (Notice & { kind: "modelReady"; hostId: string; planId: string | null; model: string; state: string; progress: ModelProgress | null })
  | (Notice & { kind: "workspaceChanged"; workspaceId: string; state: WorkspaceState; hostId: string | null; note: string })
  | (Notice & { kind: "approvalWaiting"; approvalId: string; credentialId: string; requestedBy: string; expiresAt: number })
  | (Notice & { kind: "approvalDecided"; approvalId: string; state: ApprovalState; decidedBy: string | null })
  | (Notice & { kind: "researchProgress"; jobId: string; state: string; text: string; step: number })

export type EventKind = GridEvent["kind"]

export interface EventFilter {
  realmId?: string
  kinds?: readonly EventKind[]
}

const handlers = new Set<{ filter: EventFilter; handler: (event: GridEvent) => void }>()
let listening: Promise<() => void> | null = null

function matches(filter: EventFilter, event: GridEvent): boolean {
  if (filter.realmId && filter.realmId !== event.realmId) return false
  return !filter.kinds || filter.kinds.includes(event.kind)
}

/** For a test, and for the day the engine emits this for real. */
export function deliver(event: GridEvent): void {
  for (const entry of handlers) if (matches(entry.filter, event)) entry.handler(event)
}

async function attach(): Promise<() => void> {
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return () => {}
  const { listen } = await import("@tauri-apps/api/event")
  return listen<GridEvent>(GRID_EVENT, event => deliver(event.payload))
}

/** One listener for the whole window, however many watchers there are. Returns the stop
 *  function. With no desktop app there is nothing to listen to and this does nothing, which is
 *  the normal case today. */
export function subscribe(filter: EventFilter, handler: (event: GridEvent) => void): () => void {
  const entry = { filter, handler }
  handlers.add(entry)
  // One listener for the window's life. If there is nothing to listen to, nothing happens and
  // the shared read below is the whole mechanism, which is the normal case today.
  listening ??= attach().catch(() => () => {})
  return () => { handlers.delete(entry) }
}

/** What a watcher sees. `loading` and `busy` are separate on purpose: a page needs something to
 *  hang a spinner on before the first answer, and something different to show while it refreshes
 *  a value that is already on the screen. */
export interface Watch<T> {
  value: T | null
  error: string
  /** Nothing has been read yet. Show a spinner and no list. */
  loading: boolean
  /** A read is in flight over a value that is already shown. Show the value and a spinner. */
  busy: boolean
}

export interface WatchStore<T> {
  readonly name: string
  snapshot(): Watch<T>
  subscribe(listener: () => void): () => void
  /** Asks at this pace until the returned function is called. The most eager holder sets the
   *  timer, so the engine is asked once however many parts of the page are watching. */
  hold(every: number): () => void
  refresh(): Promise<void>
}

const stores = new Map<string, WatchStore<unknown>>()

function make<T>(name: string, read: () => Promise<T>, options: { on?: readonly EventKind[] }): WatchStore<T> {
  let snapshot: Watch<T> = { value: null, error: "", loading: true, busy: false }
  const listeners = new Set<() => void>()
  const paces = new Map<symbol, number>()
  let timer = 0
  let pending: Promise<void> | null = null

  const publish = (next: Watch<T>) => {
    snapshot = next
    for (const listener of listeners) listener()
  }

  /** One read at a time, however many watchers ask. A second ask while one is in flight joins
   *  it rather than starting another, which is what keeps the hub asked once. */
  const refresh = (): Promise<void> => {
    pending ??= (() => {
      publish({ ...snapshot, loading: snapshot.value === null, busy: snapshot.value !== null })
      return read()
        .then(value => publish({ value, error: "", loading: false, busy: false }))
        .catch((reason: unknown) => publish({ value: snapshot.value, error: reason instanceof Error ? reason.message : String(reason), loading: false, busy: false }))
        .finally(() => { pending = null })
    })()
    return pending
  }

  const schedule = () => {
    if (typeof window === "undefined") return
    window.clearTimeout(timer)
    if (!paces.size) return
    timer = window.setTimeout(() => { void refresh().finally(schedule) }, Math.min(...paces.values()))
  }

  let stopEvents: (() => void) | null = null

  return {
    name,
    snapshot: () => snapshot,
    subscribe(listener) {
      listeners.add(listener)
      return () => { listeners.delete(listener) }
    },
    hold(every) {
      const key = Symbol(name)
      paces.set(key, every)
      if (options.on?.length && !stopEvents) stopEvents = subscribe({ kinds: options.on }, () => { void refresh() })
      void refresh()
      schedule()
      return () => {
        paces.delete(key)
        schedule()
        if (!paces.size && stopEvents) { stopEvents(); stopEvents = null }
      }
    },
    refresh,
  }
}

/** The one read behind a name. Asking twice for the same name gives the same store, which is
 *  what makes several parts of a page share one call. */
export function watch<T>(name: string, read: () => Promise<T>, options: { on?: readonly EventKind[] } = {}): WatchStore<T> {
  const found = stores.get(name)
  if (found) return found as WatchStore<T>
  const made = make(name, read, options)
  stores.set(name, made as WatchStore<unknown>)
  return made
}

/** Forgets every shared read. For a test that wants a clean window. */
export function forgetWatches(): void {
  stores.clear()
}
