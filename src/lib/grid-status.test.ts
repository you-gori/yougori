import { describe, expect, it } from "vitest"
import type { GridComputer } from "@/api/grid-api"
import { computerStatus, progressFraction, progressText } from "@/lib/grid-status"

const computer = (over: Partial<GridComputer> = {}): GridComputer => ({
  id: "m1", name: "Design laptop", platform: "windows", joinedAt: "", capable: true, excluded: false, planId: "p1",
  jobs: 0, online: true, lastSeenSeconds: 1, address: null, appVersion: "1.0.21", running: 0, models: [], ...over,
})

describe("progressText", () => {
  it("counts the bytes of a download and names the phase otherwise", () => {
    expect(progressText({ phase: "downloading", done: 3.2e9, total: 16e9, rate: 45.5e6 }, "Qwen/Qwen3-8B"))
      .toBe("Downloading Qwen/Qwen3-8B · 3.2 of 16.0 GB · 46 MB/s")
    expect(progressText({ phase: "downloading", done: 0, total: 0, rate: 0 }, "Qwen/Qwen3-8B")).toBe("Downloading Qwen/Qwen3-8B")
    expect(progressText({ phase: "verifying", done: 1, total: 2, rate: 0 }, "M")).toBe("Checking the downloaded files of M")
    expect(progressText({ phase: "queued", done: 0, total: 0, rate: 0 }, "M")).toBe("Waiting for GPU memory to load M")
  })

  it("gives a fraction only where bytes are counted", () => {
    expect(progressFraction({ phase: "downloading", done: 4e9, total: 16e9, rate: 0 })).toBe(0.25)
    expect(progressFraction({ phase: "downloading", done: 9, total: 0, rate: 0 })).toBeUndefined()
    expect(progressFraction({ phase: "loading", done: 0, total: 0, rate: 0 })).toBeUndefined()
    expect(progressFraction(undefined)).toBeUndefined()
    expect(progressFraction({ phase: "downloading", done: 20, total: 10, rate: 0 })).toBe(1)
  })
})

describe("computerStatus", () => {
  it("says what a computer is doing, in plain words", () => {
    const downloading = computerStatus(computer({ models: [{ model: "Qwen/Qwen3-8B", state: "loading", progress: { phase: "downloading", done: 8e9, total: 16e9, rate: 0 } }] }), "Qwen/Qwen3-8B")
    expect(downloading).toEqual({ text: "Downloading Qwen/Qwen3-8B · 8.0 of 16.0 GB", tone: "wait", fraction: 0.5 })
    expect(computerStatus(computer({ models: [{ model: "M", state: "available" }] }), "M")).toEqual({ text: "Ready · serving M", tone: "ok" })
    expect(computerStatus(computer({ models: [{ model: "M", state: "busy" }] }), "M")).toEqual({ text: "Answering a request · M", tone: "busy" })
    expect(computerStatus(computer({ models: [{ model: "M", state: "person_active" }] }), "M")).toEqual({ text: "Paused while its person works · M", tone: "wait" })
    expect(computerStatus(computer({ models: [{ model: "M", state: "error", reason: "Out of disk" }] }), "M")).toEqual({ text: "Out of disk", tone: "error" })
  })

  it("explains why a computer is doing nothing", () => {
    expect(computerStatus(computer({ excluded: true, models: [{ model: "M", state: "available" }] }), "M")).toEqual({ text: "Left out · gets no model and no work", tone: "off" })
    expect(computerStatus(computer({ capable: false }), undefined)).toEqual({ text: "Can't run models (no supported GPU)", tone: "off" })
    expect(computerStatus(computer({ planId: null }), undefined)).toEqual({ text: "Waiting for a model · assign one below", tone: "wait" })
    expect(computerStatus(computer({ online: false }), "M")).toEqual({ text: "Offline · will run M", tone: "off" })
    // Assigned, but it has not reported on the model yet.
    expect(computerStatus(computer(), "M")).toEqual({ text: "Starting M", tone: "wait" })
  })
})
