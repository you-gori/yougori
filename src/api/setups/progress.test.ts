import { expect, it, vi } from "vitest"
import { createSetupFeed, FEED_BREAKER_FAILURES, FEED_DETAIL_MAX_AGE_MS, FEED_FAILING_MS, FEED_FAST_MS, FEED_IDLE_MS, FEED_SLOW_MS } from "./progress"
import { SetupCommandError, SetupUnavailableError } from "./setups-api"
import type { OperationProgress, SetupDetail, SetupSummary } from "./types"

/** Timers the test runs by hand, so nothing waits on a clock. */
function manualTimers() {
  const queue: { run(): void; ms: number }[] = []
  let hidden = false
  return {
    timers: {
      set: (run: () => void, ms: number) => { const entry = { run, ms }; queue.push(entry); return entry },
      clear: (handle: unknown) => { const at = queue.indexOf(handle as never); if (at !== -1) queue.splice(at, 1) },
      hidden: () => hidden,
    },
    pending: () => queue.map(entry => entry.ms),
    async fire() { const entry = queue.shift(); entry?.run(); await new Promise(resolve => setTimeout(resolve, 0)) },
    hide(value: boolean) { hidden = value },
  }
}

const summary = (over: Partial<SetupSummary> = {}): SetupSummary => ({ setupId: "s1", name: "Acme", source: { kind: "installed_setup", setupId: "x" }, state: "running", createdAt: 1, ...over })
const detail = (over: Partial<SetupDetail> = {}): SetupDetail => ({ summary: summary(), revision: 1, capabilities: [], resources: [], ...over })
const progress = (over: Partial<OperationProgress> = {}): OperationProgress => ({ operation: { operationId: "op-1", setupId: "s1" }, state: "applying", events: [], nextCursor: 0, ...over })
const settle = () => new Promise(resolve => setTimeout(resolve, 0))

it("asks once for every watcher, and stops asking when nobody watches", async () => {
  const api = { list: vi.fn().mockResolvedValue([summary()]), get: vi.fn().mockResolvedValue(detail()), operation: vi.fn() }
  const clock = manualTimers()
  const feed = createSetupFeed(api, clock.timers)
  const stopA = feed.subscribe(() => undefined)
  const stopB = feed.subscribe(() => undefined)
  await settle()
  expect(api.list).toHaveBeenCalledTimes(1)
  expect(feed.getSnapshot().setups).toHaveLength(1)
  expect(clock.pending()).toEqual([FEED_IDLE_MS])
  stopA(); stopB()
  expect(clock.pending()).toEqual([])
})

it("reads quickly while an operation moves, backs off when nothing changes, and reads each event once", async () => {
  const running = summary({ currentOperation: { operationId: "op-1", setupId: "s1" } })
  const api = {
    list: vi.fn().mockResolvedValue([running]),
    get: vi.fn().mockResolvedValue(detail()),
    operation: vi.fn()
      .mockResolvedValueOnce(progress({ events: [{ cursor: 1, at: 1, step: "storage", message: "Reserving storage" }], nextCursor: 1 }))
      .mockResolvedValueOnce(progress({ events: [], nextCursor: 1 }))
      .mockResolvedValueOnce(progress({ events: [], nextCursor: 1 }))
      .mockResolvedValue(progress({ state: "completed", events: [{ cursor: 2, at: 2, step: "done", message: "Done" }], nextCursor: 2 })),
  }
  const clock = manualTimers()
  const feed = createSetupFeed(api, clock.timers)
  feed.subscribe(() => undefined)
  await settle()
  expect(clock.pending()).toEqual([FEED_FAST_MS])
  await clock.fire()
  expect(clock.pending()).toEqual([FEED_FAST_MS * 2])
  expect(api.operation).toHaveBeenLastCalledWith("op-1", 1)
  await clock.fire()
  expect(clock.pending()).toEqual([FEED_FAST_MS * 4])
  await clock.fire()
  const view = feed.getSnapshot().operations["op-1"]!
  expect(view.state).toBe("completed")
  expect(view.events.map(event => event.message)).toEqual(["Reserving storage", "Done"])
  // The finished operation's setup is read once more, then the feed rests.
  expect(clock.pending()[0]).toBeLessThanOrEqual(FEED_SLOW_MS)
  await clock.fire()
  expect(clock.pending()).toEqual([FEED_IDLE_MS])
  expect(api.operation).toHaveBeenCalledTimes(4)
})

it("stops for good when this build has no setups, until somebody asks again", async () => {
  const api = { list: vi.fn().mockRejectedValue(new SetupUnavailableError("setup_list")), get: vi.fn(), operation: vi.fn() }
  const clock = manualTimers()
  const feed = createSetupFeed(api, clock.timers)
  feed.subscribe(() => undefined)
  await settle()
  expect(feed.getSnapshot()).toMatchObject({ unavailable: true, setups: null })
  expect(clock.pending()).toEqual([])
  await feed.refresh()
  expect(api.list).toHaveBeenCalledTimes(2)
})

it("keeps what it had when a read fails, says why, and waits longer before the next", async () => {
  const api = { list: vi.fn().mockResolvedValueOnce([summary()]).mockRejectedValueOnce(new Error("The engine is busy.")), get: vi.fn().mockResolvedValue(detail()), operation: vi.fn() }
  const clock = manualTimers()
  const feed = createSetupFeed(api, clock.timers)
  feed.subscribe(() => undefined)
  await settle()
  await clock.fire()
  expect(feed.getSnapshot()).toMatchObject({ error: "The engine is busy.", setups: [summary()] })
  expect(clock.pending()[0]).toBeGreaterThan(FEED_IDLE_MS)
})

it("does not ask while the window is hidden", async () => {
  const api = { list: vi.fn().mockResolvedValue([]), get: vi.fn(), operation: vi.fn() }
  const clock = manualTimers()
  clock.hide(true)
  const feed = createSetupFeed(api, clock.timers)
  feed.subscribe(() => undefined)
  await settle()
  expect(api.list).not.toHaveBeenCalled()
  expect(clock.pending()).toEqual([FEED_SLOW_MS])
  clock.hide(false)
  await clock.fire()
  expect(api.list).toHaveBeenCalledTimes(1)
})

it("reads a quiet setup's detail again when its summary changes and at least once a minute", async () => {
  const api = { list: vi.fn().mockResolvedValue([summary()]), get: vi.fn().mockResolvedValue(detail()), operation: vi.fn() }
  const clock = manualTimers()
  let now = 0
  const feed = createSetupFeed(api, { ...clock.timers, now: () => now })
  feed.subscribe(() => undefined)
  await settle()
  expect(api.get).toHaveBeenCalledTimes(1)
  await clock.fire()
  expect(api.get).toHaveBeenCalledTimes(1)
  api.list.mockResolvedValue([summary({ health: "needs_sign_in" })])
  await clock.fire()
  expect(api.get).toHaveBeenCalledTimes(2)
  now += FEED_DETAIL_MAX_AGE_MS
  await clock.fire()
  expect(api.get).toHaveBeenCalledTimes(3)
  await feed.refresh()
  expect(api.get).toHaveBeenCalledTimes(4)
})

it("shows every kept step of an operation opened again, and says so when old ones were dropped", async () => {
  const api = {
    list: vi.fn().mockResolvedValue([summary()]),
    get: vi.fn().mockResolvedValue(detail()),
    operation: vi.fn().mockImplementation(async (_id: string, cursor: number | null) => progress({
      state: "completed",
      nextCursor: 60,
      events: cursor ? [] : Array.from({ length: 60 }, (_, at) => ({ cursor: at + 1, at, step: `s${at}`, message: `Step ${at}` })),
    })),
  }
  const clock = manualTimers()
  const feed = createSetupFeed(api, clock.timers)
  feed.subscribe(() => undefined)
  await settle()
  const stop = feed.watch("op-1")
  await settle()
  expect(feed.getSnapshot().operations["op-1"]).toMatchObject({ truncated: true })
  expect(feed.getSnapshot().operations["op-1"]!.events).toHaveLength(50)
  stop()
  await feed.refresh()
  expect(feed.getSnapshot().operations["op-1"]).toBeUndefined()
  feed.watch("op-1")
  await settle()
  await feed.refresh()
  expect(api.operation).toHaveBeenLastCalledWith("op-1", null)
  expect(feed.getSnapshot().operations["op-1"]!.events).toHaveLength(50)
})

it("keeps reading the rest when one operation or one setup can't be read", async () => {
  const api = {
    list: vi.fn().mockResolvedValue([summary({ currentOperation: { operationId: "op-gone", setupId: "s1" } }), summary({ setupId: "s2" })]),
    get: vi.fn().mockImplementation(async (id: string) => { if (id === "s1") throw new SetupCommandError("Not readable."); return detail() }),
    operation: vi.fn().mockRejectedValue(new SetupCommandError("Gone.", { code: "operation_not_found" })),
  }
  const clock = manualTimers()
  const feed = createSetupFeed(api, clock.timers)
  feed.subscribe(() => undefined)
  await settle()
  const snapshot = feed.getSnapshot()
  expect(snapshot.error).toBe("")
  expect(snapshot.setups).toHaveLength(2)
  expect(Object.keys(snapshot.details)).toEqual(["s2"])
  expect(snapshot.operations).toEqual({})
})

/** Real timer functions driven by Vitest's fake clock, including the retry deadline. */
function breakerFixture() {
  vi.useFakeTimers()
  vi.setSystemTime(1_000_000)
  const api = { list: vi.fn().mockRejectedValue(new Error("Connection failed.")), get: vi.fn(), operation: vi.fn() }
  const feed = createSetupFeed(api, {
    set: (run, ms) => setTimeout(run, ms),
    clear: handle => clearTimeout(handle as ReturnType<typeof setTimeout>),
    hidden: () => false,
    now: () => Date.now(),
  })
  const stop = feed.subscribe(() => undefined)
  return { api, feed, stop }
}

it("opens one shared breaker after three failures, doubles retries, and caps them", async () => {
  const { api, feed, stop } = breakerFixture()
  try {
    await vi.advanceTimersByTimeAsync(0)
    expect(feed.getSnapshot().breaker).toMatchObject({ open: false, consecutiveFailures: 1, message: "" })
    for (const elapsed of [2_000, 4_000]) await vi.advanceTimersByTimeAsync(elapsed)
    expect(api.list).toHaveBeenCalledTimes(FEED_BREAKER_FAILURES)
    expect(feed.getSnapshot().breaker).toEqual({
      open: true, consecutiveFailures: 3, retryAt: Date.now() + 8_000, retryInMs: 8_000,
      message: "Yougori's engine isn't answering. Trying again in 8 seconds.",
    })
    await vi.advanceTimersByTimeAsync(7_999)
    expect(api.list).toHaveBeenCalledTimes(3)
    await vi.advanceTimersByTimeAsync(1)
    expect(feed.getSnapshot().breaker.retryInMs).toBe(16_000)
    await vi.advanceTimersByTimeAsync(16_000)
    expect(feed.getSnapshot().breaker.retryInMs).toBe(32_000)
    await vi.advanceTimersByTimeAsync(32_000)
    expect(feed.getSnapshot().breaker.retryInMs).toBe(FEED_FAILING_MS)
    await vi.advanceTimersByTimeAsync(FEED_FAILING_MS)
    expect(feed.getSnapshot().breaker.retryInMs).toBe(FEED_FAILING_MS)
    expect(vi.getTimerCount()).toBe(1)
  } finally { stop(); vi.useRealTimers() }
})

it("closes on the first successful automatic retry and clears the warning", async () => {
  const { api, feed, stop } = breakerFixture()
  try {
    await vi.advanceTimersByTimeAsync(6_000)
    expect(feed.getSnapshot().breaker.open).toBe(true)
    api.list.mockResolvedValue([])
    await vi.advanceTimersByTimeAsync(8_000)
    expect(feed.getSnapshot()).toMatchObject({ error: "", setups: [], breaker: { open: false, consecutiveFailures: 0, retryAt: null, retryInMs: 0, message: "" } })
    expect(api.list).toHaveBeenCalledTimes(4)
    expect(vi.getTimerCount()).toBe(1)
    await vi.advanceTimersByTimeAsync(FEED_IDLE_MS - 1)
    expect(api.list).toHaveBeenCalledTimes(4)
  } finally { stop(); vi.useRealTimers() }
})

it("a manual refresh bypasses the open deadline and failure retains the backoff", async () => {
  const { api, feed, stop } = breakerFixture()
  try {
    await vi.advanceTimersByTimeAsync(6_000)
    const before = Date.now()
    await feed.refresh()
    expect(Date.now()).toBe(before)
    expect(api.list).toHaveBeenCalledTimes(4)
    expect(feed.getSnapshot().breaker).toMatchObject({ open: true, consecutiveFailures: 4, retryInMs: 16_000 })
    api.list.mockResolvedValue([])
    await feed.refresh()
    expect(Date.now()).toBe(before)
    expect(api.list).toHaveBeenCalledTimes(5)
    expect(feed.getSnapshot().breaker.open).toBe(false)
    expect(vi.getTimerCount()).toBe(1)
  } finally { stop(); vi.useRealTimers() }
})

it("new operation watchers and resubscriptions cannot bypass the open breaker", async () => {
  const { api, feed, stop } = breakerFixture()
  let stopAgain: () => void = () => undefined
  let unwatch: () => void = () => undefined
  try {
    await vi.advanceTimersByTimeAsync(6_000)
    const retryAt = feed.getSnapshot().breaker.retryAt
    unwatch = feed.watch("op-later")
    await vi.advanceTimersByTimeAsync(0)
    expect(api.list).toHaveBeenCalledTimes(3)
    stop()
    expect(vi.getTimerCount()).toBe(0)
    stopAgain = feed.subscribe(() => undefined)
    await vi.advanceTimersByTimeAsync(0)
    expect(api.list).toHaveBeenCalledTimes(3)
    expect(feed.getSnapshot().breaker.retryAt).toBe(retryAt)
    await vi.advanceTimersByTimeAsync(8_000)
    expect(api.list).toHaveBeenCalledTimes(4)
  } finally { unwatch(); stop(); stopAgain(); vi.useRealTimers() }
})

it("unsupported builds stop polling and do not retain a connection breaker", async () => {
  const { api, feed, stop } = breakerFixture()
  try {
    await vi.advanceTimersByTimeAsync(6_000)
    api.list.mockRejectedValue(new SetupUnavailableError("setup_list"))
    await feed.refresh()
    expect(feed.getSnapshot()).toMatchObject({ unavailable: true, breaker: { open: false, consecutiveFailures: 0, message: "" } })
    expect(vi.getTimerCount()).toBe(0)
  } finally { stop(); vi.useRealTimers() }
})
