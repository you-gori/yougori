// @vitest-environment jsdom
import { act, cleanup, renderHook } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { ReactNode } from "react"
import { platformApi } from "@/api/platform-api"
import seed from "@/data/seed.json"
import type { PlatformState } from "@/types/platform"
import { PlatformProvider, usePlatform } from "./platform-context"

vi.mock("@/api/platform-api", () => ({ platformApi: { getState: vi.fn(), refreshHostMetrics: vi.fn() } }))
vi.mock("@/components/ui/toast", () => ({ toastManager: { add: vi.fn() } }))

const wrapper = ({ children }: { children: ReactNode }) => <PlatformProvider>{children}</PlatformProvider>
let state: PlatformState
beforeEach(() => {
  vi.useFakeTimers()
  state = structuredClone(seed) as PlatformState
  state.environments = []
  vi.mocked(platformApi.getState).mockResolvedValue(state)
})
afterEach(() => { cleanup(); vi.useRealTimers(); vi.resetAllMocks() })

it("keeps one polling loop when the window is hidden or shown during a refresh", async () => {
  let finish!: () => void
  vi.mocked(platformApi.refreshHostMetrics).mockImplementation(() => new Promise(resolve => { finish = () => resolve(state) }))
  renderHook(usePlatform, { wrapper })
  await act(async () => { await vi.advanceTimersByTimeAsync(0) })
  // The first refresh starts after the idle delay and is still running when the window is shown.
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
  expect(platformApi.refreshHostMetrics).toHaveBeenCalledTimes(1)
  act(() => { document.dispatchEvent(new Event("visibilitychange")) })
  await act(async () => { finish(); await vi.advanceTimersByTimeAsync(0) })
  vi.mocked(platformApi.refreshHostMetrics).mockResolvedValue(state)
  // One loop refreshes once per idle delay; two loops would refresh twice.
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
  expect(platformApi.refreshHostMetrics).toHaveBeenCalledTimes(2)
})
