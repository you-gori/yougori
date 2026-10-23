// @vitest-environment jsdom
import { act, renderHook, cleanup } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { useSwarmActions } from "./use-swarm-actions"

vi.mock("@/components/ui/toast", () => ({ toastManager: { add: vi.fn() } }))
afterEach(cleanup)

it("queues Resume behind an unfinished Pause instead of losing the click", async () => {
  let finishPause!: () => void
  const paused = new Promise<void>(resolve => { finishPause = resolve })
  const pause = vi.fn(() => paused)
  const resume = vi.fn(async () => {})
  const { result } = renderHook(() => useSwarmActions(vi.fn(async () => {})))
  let completed!: Promise<void>
  await act(async () => { void result.current.run("Pause", pause) })
  await act(async () => { completed = result.current.run("Resume", resume) })
  expect(pause).toHaveBeenCalledOnce()
  expect(resume).not.toHaveBeenCalled()
  expect(result.current.busy).toContain("queued")
  await act(async () => { finishPause(); await completed })
  expect(resume).toHaveBeenCalledOnce()
  expect(result.current.busy).toBe("")
})

it("continues with Resume after a failed action or refresh", async () => {
  const refresh = vi.fn(async () => { throw new Error("Offline") })
  const resume = vi.fn(async () => {})
  const { result } = renderHook(() => useSwarmActions(refresh))
  await act(async () => {
    void result.current.run("Pause", async () => { throw new Error("Timed out") })
    await result.current.run("Resume", resume)
  })
  expect(resume).toHaveBeenCalledOnce()
  expect(result.current.busy).toBe("")
})
