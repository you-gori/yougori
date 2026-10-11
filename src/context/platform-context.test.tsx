// @vitest-environment jsdom
import { act, cleanup, fireEvent, screen, renderHook, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import type { ReactNode } from "react"
import { platformApi } from "@/api/platform-api"
import seed from "@/data/seed.json"
import type { CreateEnvironmentRequest, Environment, PlatformState } from "@/types/platform"
import { PlatformProvider, usePlatform } from "./platform-context"
import { toastManager } from "@/components/ui/toast"

vi.mock("@/api/platform-api", () => ({ platformApi: {
  getState: vi.fn(), createEnvironment: vi.fn(), setEnvironmentStatus: vi.fn(), openEnvironmentWindow: vi.fn(), deleteEnvironment: vi.fn(),
  factoryResetEnvironment: vi.fn(), recoverContainerRuntime: vi.fn(), recoverVmRuntime: vi.fn(),
} }))
vi.mock("@/components/ui/toast", () => ({ toastManager: { add: vi.fn() } }))

function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (reason: Error) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
const wrapper = ({ children }: { children: ReactNode }) => <PlatformProvider pollHostMetrics={false}>{children}</PlatformProvider>
let state: PlatformState
beforeEach(() => {
  vi.resetAllMocks()
  state = structuredClone(seed) as PlatformState
  state.environments = ["Alpha", "Beta"].map(id => ({ id, status: "stopped", kind: "container" }) as Environment)
  vi.mocked(platformApi.getState).mockResolvedValue(state)
})
afterEach(cleanup)

describe("environment action feedback", () => {
  it("does not let a delayed refresh bring back a deleted environment", async () => {
    const refresh = deferred<PlatformState>()
    vi.mocked(platformApi.deleteEnvironment).mockResolvedValue({ ...state, environments: state.environments.slice(1) })
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    vi.mocked(platformApi.getState).mockReturnValue(refresh.promise)
    let task!: Promise<void>
    act(() => { task = result.current.refreshPlatform() })
    await act(async () => { await result.current.deleteEnvironment("Alpha") })
    await act(async () => { refresh.resolve(state); await task })
    expect(result.current.state?.environments.map(e => e.id)).toEqual(["Beta"])
  })

  it("keeps the newest engine state when replies arrive out of order", async () => {
    state.stateRevision = 1
    const slow = deferred<PlatformState>()
    const older = { ...state, stateRevision: 2, environments: state.environments.map(e => e.id === "Alpha" ? { ...e, status: "running" } : e) } as PlatformState
    const newer = { ...state, stateRevision: 3, environments: state.environments.map(e => ({ ...e, status: "running" })) } as PlatformState
    vi.mocked(platformApi.setEnvironmentStatus).mockImplementation(id => id === "Alpha" ? slow.promise : Promise.resolve(newer))
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    let first!: Promise<void>
    act(() => { first = result.current.setEnvironmentStatus("Alpha", "running") })
    await act(async () => { await result.current.setEnvironmentStatus("Beta", "running") })
    await act(async () => { slow.resolve(older); await first })
    expect(result.current.state?.stateRevision).toBe(3)
    expect(result.current.state?.environments.map(e => e.status)).toEqual(["running", "running"])
  })

  it("opens a stopped remote entry without implicitly powering on the owner's target", async () => {
    state.environments[0] = { ...state.environments[0]!, kind: "cloud", runtime: "shared://tunnel/host/share-id", status: "stopped" }
    vi.mocked(platformApi.openEnvironmentWindow).mockResolvedValue(true)
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    await act(async () => { await result.current.openEnvironmentWindow("Alpha") })
    expect(platformApi.setEnvironmentStatus).not.toHaveBeenCalled()
    expect(platformApi.openEnvironmentWindow).toHaveBeenCalledWith("Alpha")
  })

  it("recovers a VM through Stop without calling container recovery", async () => {
    vi.mocked(platformApi.setEnvironmentStatus).mockRejectedValueOnce(new Error("[YOUGORI_VM_RUNTIME_BUSY] locked")).mockResolvedValue(state)
    vi.mocked(platformApi.recoverVmRuntime).mockResolvedValue(state)
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    let task!: Promise<void>
    act(() => { task = result.current.setEnvironmentStatus("Alpha", "stopped") })
    await screen.findByText(/Recovery tries a normal shutdown/)
    expect(platformApi.recoverVmRuntime).not.toHaveBeenCalled()
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: /^Stop$/ })); await task })
    expect(platformApi.recoverVmRuntime).toHaveBeenCalledWith("Alpha")
    expect(platformApi.recoverContainerRuntime).not.toHaveBeenCalled()
    expect(platformApi.setEnvironmentStatus).toHaveBeenCalledTimes(2)
    expect(result.current.environmentActions).toEqual({})
  })

  it("cancelling VM recovery leaves the runtime alone and unlocks Stop", async () => {
    vi.mocked(platformApi.setEnvironmentStatus).mockRejectedValue(new Error("[YOUGORI_VM_RUNTIME_BUSY] locked"))
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    let task!: Promise<unknown>
    act(() => { task = result.current.setEnvironmentStatus("Alpha", "stopped").catch(error => error) })
    await screen.findByText(/Recovery tries a normal shutdown/)
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Cancel" })); await task })
    expect(platformApi.recoverVmRuntime).not.toHaveBeenCalled()
    expect(platformApi.setEnvironmentStatus).toHaveBeenCalledTimes(1)
    expect(result.current.environmentActions).toEqual({})
  })
  it("offers recovery from Stop and retries only after confirmation", async () => {
    vi.mocked(platformApi.setEnvironmentStatus).mockRejectedValueOnce(new Error("[YOUGORI_RUNTIME_BUSY] locked")).mockResolvedValue(state)
    vi.mocked(platformApi.recoverContainerRuntime).mockResolvedValue(state)
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    let task!: Promise<void>
    act(() => { task = result.current.setEnvironmentStatus("Alpha", "stopped") })
    await screen.findByText("Stop the abandoned runtime?")
    expect(platformApi.recoverContainerRuntime).not.toHaveBeenCalled()
    expect(result.current.environmentActions.Alpha).toBe("stopping")
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: /^Stop$/ })); await task })
    expect(platformApi.recoverContainerRuntime).toHaveBeenCalledWith("Alpha")
    expect(platformApi.setEnvironmentStatus).toHaveBeenCalledTimes(2)
    expect(result.current.environmentActions).toEqual({})
  })
  it("keeps a successful deletion committed and shows persistent cleanup warnings", async () => {
    const after = { ...state, environments: state.environments.slice(1), host: { ...state.host, storageDrive: "C:\\", totalStorageGb: 100, usedStorageGb: 80 }, storageCleanup: { reclaimedCacheBytes: 0, warnings: ["A base image is locked; cached files were kept."] } }
    vi.mocked(platformApi.deleteEnvironment).mockResolvedValue(after)
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    await act(async () => { await result.current.deleteEnvironment("Alpha") })
    expect(result.current.state?.environments.map(e => e.id)).toEqual(["Beta"])
    expect(result.current.state?.host.usedStorageGb).toBe(80)
    expect(result.current.error).toBeNull()
    expect(toastManager.add).toHaveBeenCalledWith(expect.objectContaining({ title: "Environment removed — cleanup incomplete", type: "warning", timeout: 0, description: expect.stringContaining("A base image is locked; cached files were kept.") }))
    expect(result.current.environmentActions).toEqual({})
  })

  it("reports reclaimed cache size without implying that original installers were deleted", async () => {
    vi.mocked(platformApi.deleteEnvironment).mockResolvedValue({ ...state, environments: [], storageCleanup: { reclaimedCacheBytes: 2 * 1_073_741_824, warnings: [] } })
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    await act(async () => { await result.current.deleteEnvironment("Alpha") })
    expect(toastManager.add).toHaveBeenCalledWith(expect.objectContaining({ type: "success", description: "2.00 GB of unused cached images also removed. Original installers and exported backups were kept." }))
  })

  it("shows reset loading globally and prevents starting the same node during reset", async () => {
    const resetting = deferred<PlatformState>()
    vi.mocked(platformApi.factoryResetEnvironment).mockReturnValue(resetting.promise)
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    let task!: Promise<void>
    act(() => { task = result.current.factoryResetEnvironment("Alpha", "Alpha") })
    expect(result.current.environmentActions.Alpha).toBe("resetting")
    await expect(result.current.setEnvironmentStatus("Alpha", "running")).rejects.toThrow()
    expect(platformApi.setEnvironmentStatus).not.toHaveBeenCalled()
    await act(async () => { resetting.resolve(state); await task })
    expect(result.current.environmentActions).toEqual({})
  })
  it.each(["container", "microVm", "fullVm"] as const)("does not let a delayed creation progress read erase a completed %s", async kind => {
    const creation = deferred<PlatformState>(), progress = deferred<PlatformState>()
    vi.mocked(platformApi.createEnvironment).mockReturnValue(creation.promise)
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    vi.mocked(platformApi.getState).mockReturnValue(progress.promise)
    let task!: Promise<void>
    act(() => {
      task = result.current.createEnvironment({ kind, name: "New environment" } as CreateEnvironmentRequest)
    })
    await waitFor(() => expect(platformApi.getState).toHaveBeenCalledTimes(2))
    const completed = structuredClone(state)
    completed.environments.push({ id: "New environment", kind, status: "stopped" } as Environment)
    await act(async () => { creation.resolve(completed); await task })
    await act(async () => { progress.resolve(state); await progress.promise })
    expect(result.current.state?.environments.at(-1)?.id).toBe("New environment")
    expect(result.current.state?.environments.at(-1)?.status).toBe("stopped")
  })

  it("keeps Start busy through Opening and rejects simultaneous conflicting actions", async () => {
    const start = deferred<PlatformState>(), open = deferred<boolean>()
    vi.mocked(platformApi.setEnvironmentStatus).mockReturnValue(start.promise)
    vi.mocked(platformApi.openEnvironmentWindow).mockReturnValue(open.promise)
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    let task!: Promise<boolean>, duplicate!: Promise<unknown>
    act(() => {
      task = result.current.openEnvironmentWindow("Alpha")
      duplicate = result.current.setEnvironmentStatus("Alpha", "stopped").catch(error => error)
    })
    expect(result.current.environmentActions).toEqual({ Alpha: "starting" })
    expect(await duplicate).toBeInstanceOf(Error)
    expect(platformApi.setEnvironmentStatus).toHaveBeenCalledTimes(1)
    expect(platformApi.openEnvironmentWindow).not.toHaveBeenCalled()
    await act(async () => {
      const running = structuredClone(state); running.environments[0]!.status = "running"
      start.resolve(running); await start.promise
    })
    expect(result.current.environmentActions).toEqual({ Alpha: "opening" })
    await act(async () => { open.resolve(true); await task })
    expect(result.current.environmentActions).toEqual({})
  })

  it("tracks different environments independently and clears failed actions for retry", async () => {
    const alpha = deferred<PlatformState>(), beta = deferred<PlatformState>()
    vi.mocked(platformApi.setEnvironmentStatus).mockImplementation(id => id === "Alpha" ? alpha.promise : beta.promise)
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    let first!: Promise<unknown>, second!: Promise<void>
    act(() => {
      first = result.current.setEnvironmentStatus("Alpha", "running").catch(error => error)
      second = result.current.setEnvironmentStatus("Beta", "stopped")
    })
    expect(result.current.environmentActions).toEqual({ Alpha: "starting", Beta: "stopping" })
    await act(async () => { alpha.reject(new Error("Start failed")); await first })
    expect(result.current.environmentActions).toEqual({ Beta: "stopping" })
    expect(result.current.error).toBe("Start failed")
    vi.mocked(platformApi.setEnvironmentStatus).mockResolvedValue(state)
    await act(async () => { await result.current.setEnvironmentStatus("Alpha", "running") })
    expect(result.current.environmentActions).toEqual({ Beta: "stopping" })
    await act(async () => { beta.resolve(state); await second })
    expect(result.current.environmentActions).toEqual({})
  })

  it("does not open a window after startup fails and also unlocks a failed window open", async () => {
    vi.mocked(platformApi.setEnvironmentStatus).mockRejectedValue(new Error("Start failed"))
    const { result } = renderHook(usePlatform, { wrapper })
    await waitFor(() => expect(result.current.loading).toBe(false))
    await act(async () => { await expect(result.current.openEnvironmentWindow("Alpha")).rejects.toThrow("Start failed") })
    expect(platformApi.openEnvironmentWindow).not.toHaveBeenCalled()
    expect(result.current.environmentActions).toEqual({})
    vi.mocked(platformApi.setEnvironmentStatus).mockResolvedValue(state)
    vi.mocked(platformApi.openEnvironmentWindow).mockRejectedValue(new Error("Window failed"))
    await act(async () => { await expect(result.current.openEnvironmentWindow("Alpha")).rejects.toThrow("Window failed") })
    expect(result.current.environmentActions).toEqual({})
  })
})
