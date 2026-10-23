// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest"
import { GRID_EVENT, deliver, forgetWatches, subscribe, watch, type GridEvent } from "@/api/grids/events"

afterEach(() => { forgetWatches(); vi.useRealTimers() })

const notice = (over: Partial<GridEvent> = {}): GridEvent =>
  ({ kind: "hostChanged", realmId: "g1", seq: 1, at: 0, hostId: "m1", online: true, excluded: false, ...over } as GridEvent)

describe("the event stream", () => {
  it("is named so it cannot be mistaken for a vault entry", () => {
    expect(GRID_EVENT).toBe("yougori-grids-news")
    expect(GRID_EVENT.startsWith("yougori-grid-")).toBe(false)
  })

  it("does nothing and breaks nothing where there is no desktop app, which is today", () => {
    const heard: GridEvent[] = []
    const stop = subscribe({}, event => heard.push(event))
    expect(typeof stop).toBe("function")
    deliver(notice())
    expect(heard).toHaveLength(1)
    stop()
    deliver(notice())
    expect(heard).toHaveLength(1)
  })

  it("gives a listener only what it asked for", () => {
    const heard: GridEvent[] = []
    const stop = subscribe({ realmId: "g1", kinds: ["modelReady"] }, event => heard.push(event))
    deliver(notice())
    deliver(notice({ kind: "modelReady", hostId: "m1", planId: null, model: "m", state: "serving", progress: null } as Partial<GridEvent>))
    deliver(notice({ kind: "modelReady", realmId: "other", hostId: "m1", planId: null, model: "m", state: "serving", progress: null } as Partial<GridEvent>))
    stop()
    expect(heard.map(event => event.kind)).toEqual(["modelReady"])
  })
})

describe("the shared read", () => {
  it("has a flag for the first wait and a different one for a refresh, so a spinner always has something to hang on", async () => {
    let answer: (value: number) => void = () => {}
    const read = vi.fn(() => new Promise<number>(done => { answer = done }))
    const store = watch("test-first", read)
    expect(store.snapshot()).toEqual({ value: null, error: "", loading: true, busy: false })

    const stop = store.hold(10_000)
    expect(store.snapshot()).toMatchObject({ loading: true, busy: false })
    answer(1)
    await vi.waitFor(() => expect(store.snapshot().value).toBe(1))
    expect(store.snapshot()).toEqual({ value: 1, error: "", loading: false, busy: false })

    const again = store.refresh()
    expect(store.snapshot()).toMatchObject({ value: 1, loading: false, busy: true })
    answer(2)
    await again
    expect(store.snapshot()).toEqual({ value: 2, error: "", loading: false, busy: false })
    stop()
  })

  it("asks once however many parts of the page are watching", async () => {
    const read = vi.fn(async () => 7)
    const store = watch("test-shared", read)
    const first = store.hold(1000)
    const second = store.hold(1000)
    await vi.waitFor(() => expect(store.snapshot().value).toBe(7))
    expect(read).toHaveBeenCalledTimes(1)
    first()
    second()
  })

  it("takes the pace of whichever watcher is most eager", async () => {
    vi.useFakeTimers()
    const read = vi.fn(async () => 1)
    const store = watch("test-pace", read)
    const slow = store.hold(10_000)
    const quick = store.hold(100)
    await vi.advanceTimersByTimeAsync(150)
    expect(read.mock.calls.length).toBeGreaterThan(1)
    quick()
    slow()
  })

  it("keeps the value on the screen when a read fails, and says why", async () => {
    let fail = false
    const store = watch("test-error", async () => { if (fail) throw new Error("The hub stopped answering"); return 3 })
    const stop = store.hold(10_000)
    await vi.waitFor(() => expect(store.snapshot().value).toBe(3))
    fail = true
    await store.refresh()
    expect(store.snapshot()).toEqual({ value: 3, error: "The hub stopped answering", loading: false, busy: false })
    stop()
  })

  it("brings the next read forward when a matching event arrives, rather than believing the event", async () => {
    const read = vi.fn(async () => 5)
    const store = watch("test-event", read, { on: ["hostChanged"] })
    const stop = store.hold(10_000)
    await vi.waitFor(() => expect(store.snapshot().value).toBe(5))
    expect(read).toHaveBeenCalledTimes(1)
    deliver(notice({ seq: 2 }))
    await vi.waitFor(() => expect(read).toHaveBeenCalledTimes(2))
    expect(store.snapshot().value).toBe(5)
    stop()
  })

  it("gives the same store back for the same name, which is what makes it shared at all", () => {
    expect(watch("test-same", async () => 1)).toBe(watch("test-same", async () => 2))
  })
})
