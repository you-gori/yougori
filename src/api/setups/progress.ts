import { useEffect, useSyncExternalStore } from "react"
import { errorText, isUnavailable, SetupCommandError, setupsApi } from "./setups-api"
import type { Diagnostic, OperationEvent, OperationState, SetupDetailView, SetupSummary } from "./types"

/** One reader of setups and their progress for the whole app.
 *
 *  Every card and dialog that shows a setup reads this one feed instead of asking the engine on
 *  its own timer. It asks only while something is watching: quickly while an operation is moving,
 *  more slowly when nothing changes, not at all while the window is hidden, and never again once
 *  the engine has said this build has no setups (until somebody asks for a refresh). Operation
 *  events are read from a cursor, so each one is fetched once.
 */
export interface OperationView {
  state: OperationState
  /** Set when it finished and failed; a cancelled one carries `operation_cancelled`. */
  error: Diagnostic | null
  /** The latest events, oldest first, at most `FEED_EVENTS`. */
  events: OperationEvent[]
  /** True when older events were dropped before this app read them. */
  truncated: boolean
}

export interface FeedState {
  /** Null until the first answer. */
  setups: SetupSummary[] | null
  details: Record<string, SetupDetailView>
  operations: Record<string, OperationView>
  unavailable: boolean
  error: string
  /** One shared connection warning for My setups, rather than a warning on every card. */
  breaker: FeedBreaker
}

export interface FeedBreaker {
  open: boolean
  consecutiveFailures: number
  /** Unix milliseconds; a page may use this to update its countdown. */
  retryAt: number | null
  retryInMs: number
  /** Prefer this line to `error` while open; don't render both warnings. */
  message: string
}

export const FEED_FAST_MS = 1_000
export const FEED_SLOW_MS = 15_000
export const FEED_IDLE_MS = 30_000
export const FEED_FAILING_MS = 60_000
export const FEED_BREAKER_FAILURES = 3
export const FEED_EVENTS = 50
/** A quiet setup's detail is read again at least this often, so a capability that becomes ready
 *  or needs a sign-in without any operation still shows it. */
export const FEED_DETAIL_MAX_AGE_MS = 60_000

const MOVING = new Set<OperationState>(["planned", "awaiting_input", "applying", "cancelling", "unknown"])
export const isMoving = (operation: Pick<OperationView, "state"> | null | undefined) => Boolean(operation && MOVING.has(operation.state))

type Api = Pick<typeof setupsApi, "list" | "get" | "operation">
type Timers = { set(run: () => void, ms: number): unknown; clear(handle: unknown): void; hidden(): boolean; now?(): number }

const browserTimers: Timers = {
  set: (run, ms) => setTimeout(run, ms),
  clear: handle => clearTimeout(handle as ReturnType<typeof setTimeout>),
  hidden: () => typeof document !== "undefined" && document.visibilityState === "hidden",
  now: () => Date.now(),
}

const CLOSED_BREAKER: FeedBreaker = { open: false, consecutiveFailures: 0, retryAt: null, retryInMs: 0, message: "" }
const EMPTY: FeedState = { setups: null, details: {}, operations: {}, unavailable: false, error: "", breaker: CLOSED_BREAKER }

export function createSetupFeed(api: Api = setupsApi, timers: Timers = browserTimers) {
  let state: FeedState = EMPTY
  const listeners = new Set<() => void>()
  const watched = new Map<string, number>()
  const cursors = new Map<string, number>()
  /** What each setup's summary was, and when, when its detail was last read. */
  const detailFor = new Map<string, { summary: string; at: number }>()
  let stale = new Set<string>()
  let everything = false
  const now = () => timers.now?.() ?? Date.now()
  let timer: unknown = null
  let delay = FEED_FAST_MS
  let reading: Promise<void> | null = null

  const publish = (next: FeedState) => {
    state = next
    for (const listener of listeners) listener()
  }
  const stopTimer = () => {
    if (timer !== null) timers.clear(timer)
    timer = null
  }
  const schedule = (ms: number) => {
    stopTimer()
    if (listeners.size) timer = timers.set(() => { timer = null; void read() }, ms)
  }

  /** Reads one operation. Its events are read on from the cursor only while they are still held
   *  here; otherwise from the start, so an operation opened again shows every step it kept. */
  async function readOperation(id: string, operations: Record<string, OperationView>) {
    const known = state.operations[id]
    if (known && !isMoving(known) && cursors.has(id)) { operations[id] = known; return }
    const read = await api.operation(id, known ? cursors.get(id) ?? null : null)
    if (Number.isFinite(read.nextCursor)) cursors.set(id, read.nextCursor)
    const before = known?.events ?? []
    const seen = new Set(before.map(event => event.cursor))
    const events = [...before, ...(read.events ?? []).filter(event => !seen.has(event.cursor))]
    operations[id] = {
      state: read.state,
      error: read.error ?? null,
      events: events.slice(-FEED_EVENTS),
      // Keeping only the latest events means the earlier ones are no longer shown.
      truncated: Boolean(known?.truncated || read.truncated || events.length > FEED_EVENTS),
    }
  }

  async function readOnce(force = false) {
    // A new watcher/subscription is not a manual retry. Keep the shared deadline even if the
    // last watcher left and stopped its timer, then another screen subscribed before it elapsed.
    const retryAt = state.breaker.retryAt
    if (!force && state.breaker.open && retryAt !== null && retryAt > now()) {
      schedule(retryAt - now())
      return
    }
    if (timers.hidden()) { schedule(FEED_SLOW_MS); return }
    try {
      const setups = await api.list()
      const operations: Record<string, OperationView> = {}
      const wanted = new Set([...watched.keys(), ...setups.flatMap(setup => setup.currentOperation ? [setup.currentOperation.operationId] : [])])
      // One operation that can't be read doesn't stop the rest. One the engine no longer has is
      // dropped; any other failure keeps what was last read of it.
      for (const id of wanted) {
        try {
          await readOperation(id, operations)
        } catch (reason) {
          if (isUnavailable(reason)) throw reason
          if (reason instanceof SetupCommandError && reason.code === "operation_not_found") continue
          if (state.operations[id]) operations[id] = state.operations[id]
        }
      }
      for (const id of [...cursors.keys()]) if (!(id in operations)) cursors.delete(id)

      // A setup's detail is read when it is new, when its summary changed (its state, health or
      // operation), while something moves on it, once after an operation on it finishes, when
      // somebody asked for a refresh, and otherwise once a minute.
      const details: Record<string, SetupDetailView> = {}
      const all = everything
      everything = false
      for (const setup of setups) {
        const current = setup.currentOperation?.operationId ?? ""
        const cached = state.details[setup.setupId]
        const moving = current ? isMoving(operations[current]) : false
        const summary = JSON.stringify(setup)
        const last = detailFor.get(setup.setupId)
        if (all || !cached || !last || last.summary !== summary || moving || stale.has(setup.setupId) || now() - last.at >= FEED_DETAIL_MAX_AGE_MS) {
          try {
            details[setup.setupId] = await api.get(setup.setupId)
            detailFor.set(setup.setupId, { summary, at: now() })
          } catch (reason) {
            // One setup that can't be read doesn't hide the others; it keeps what was last read.
            if (isUnavailable(reason)) throw reason
            if (cached) details[setup.setupId] = cached
          }
        } else {
          details[setup.setupId] = cached
        }
      }
      // An operation that just finished gets its setup read once more, after the engine has
      // written the end of it.
      stale = new Set(setups.filter(setup => {
        const id = setup.currentOperation?.operationId
        return id && state.operations[id] && isMoving(state.operations[id]) && !isMoving(operations[id])
      }).map(setup => setup.setupId))

      const next: FeedState = { setups, details, operations, unavailable: false, error: "", breaker: CLOSED_BREAKER }
      const changed = JSON.stringify(next) !== JSON.stringify(state)
      const moving = Object.values(operations).some(isMoving) || stale.size > 0
      delay = !moving ? FEED_IDLE_MS : changed ? FEED_FAST_MS : Math.min(delay * 2, FEED_SLOW_MS)
      if (changed) publish(next)
      schedule(delay)
    } catch (reason) {
      if (isUnavailable(reason)) {
        // Nothing to ask again: this build has no setups. An explicit refresh still tries.
        if (!state.unavailable) publish({ ...EMPTY, unavailable: true })
        stopTimer()
        return
      }
      delay = Math.min(Math.max(delay * 2, 2_000), FEED_FAILING_MS)
      const consecutiveFailures = state.breaker.consecutiveFailures + 1
      const open = consecutiveFailures >= FEED_BREAKER_FAILURES
      const breaker: FeedBreaker = {
        open,
        consecutiveFailures,
        retryAt: now() + delay,
        retryInMs: delay,
        message: open ? `Yougori's engine isn't answering. Trying again in ${Math.ceil(delay / 1_000)} seconds.` : "",
      }
      publish({ ...state, error: errorText(reason), breaker })
      schedule(delay)
    }
  }

  function read(force = false) {
    reading ??= readOnce(force).finally(() => { reading = null })
    return reading
  }

  const feed = {
    subscribe(listener: () => void) {
      listeners.add(listener)
      if (listeners.size === 1 && timer === null && !reading && !state.unavailable) void read()
      return () => {
        listeners.delete(listener)
        if (!listeners.size) stopTimer()
      }
    },
    getSnapshot: () => state,
    /** Reads now, for example straight after an action, and starts quick again. */
    async refresh(setupId?: string) {
      stopTimer()
      // An explicit retry bypasses the deadline; a failed retry still backs off instead of
      // resetting an already-open breaker to its shortest interval.
      if (!state.breaker.open) delay = FEED_FAST_MS
      if (setupId) stale.add(setupId)
      else everything = true
      await reading
      stopTimer()
      await read(true)
    },
    /** Keeps one operation read in full while something shows it. */
    watch(operationId: string) {
      watched.set(operationId, (watched.get(operationId) ?? 0) + 1)
      if (listeners.size && !state.operations[operationId] && !state.breaker.open) void feed.refresh()
      return () => {
        const left = (watched.get(operationId) ?? 1) - 1
        if (left > 0) watched.set(operationId, left)
        else watched.delete(operationId)
      }
    },
  }
  return feed
}

export type SetupFeed = ReturnType<typeof createSetupFeed>

export const setupFeed = createSetupFeed()

export function useSetupFeed(feed: SetupFeed = setupFeed): FeedState {
  return useSyncExternalStore(feed.subscribe, feed.getSnapshot, feed.getSnapshot)
}

/** One operation, kept fresh while this is mounted. */
export function useOperation(operationId: string | null, feed: SetupFeed = setupFeed): OperationView | null {
  const snapshot = useSetupFeed(feed)
  useEffect(() => operationId ? feed.watch(operationId) : undefined, [operationId, feed])
  return operationId ? snapshot.operations[operationId] ?? null : null
}
