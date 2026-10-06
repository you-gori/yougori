// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { CudaUpdateAction } from "./cuda-update-action"
import { StorageAllocationEditor } from "./storage-allocation-editor"
import { platformApi } from "@/api/platform-api"
import { gpuApi, type CudaRuntimeStatus } from "@/api/gpu-api"
import type { Environment } from "@/types/platform"

vi.mock("@/api/gpu-api", () => ({ gpuApi: { cudaStatus: vi.fn(), installCuda: vi.fn() } }))
vi.mock("@/api/platform-api", () => ({ platformApi: { getStorageAllocation: vi.fn() } }))
const environment = { id: "company", provider: "yougoriCuda", storageDrive: "D:\\", lastError: "A CUDA runtime update is required for this Yougori version." } as Environment
const current: CudaRuntimeStatus = { supported: true, installed: true, running: false, updateAvailable: false, detail: "Ready" }
beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(gpuApi.cudaStatus).mockResolvedValue({ ...current, updateAvailable: true })
  vi.mocked(gpuApi.installCuda).mockResolvedValue(current)
})
afterEach(cleanup)

it("updates the affected drive once, keeps progress visible and refreshes only after success", async () => {
  let finish!: (status: CudaRuntimeStatus) => void
  vi.mocked(gpuApi.installCuda).mockImplementation(() => new Promise(resolve => { finish = resolve }))
  const updated = vi.fn()
  render(<CudaUpdateAction environment={environment} onUpdated={updated} />)
  const button = screen.getByRole("button", { name: "Update now" })
  fireEvent.click(button); fireEvent.click(button)
  await vi.waitFor(() => expect(gpuApi.installCuda).toHaveBeenCalledTimes(1))
  expect(gpuApi.cudaStatus).toHaveBeenCalledWith("D:\\")
  expect(gpuApi.installCuda).toHaveBeenCalledWith("D:\\")
  expect((button as HTMLButtonElement).disabled).toBe(true)
  expect(updated).not.toHaveBeenCalled()
  await act(async () => finish(current))
  expect(updated).toHaveBeenCalledTimes(1)
  expect(screen.getByRole("status").textContent).toContain("Your disk was kept")
})

it("does not update or stop a running runtime", async () => {
  vi.mocked(gpuApi.cudaStatus).mockResolvedValue({ ...current, running: true, updateAvailable: true })
  render(<CudaUpdateAction environment={environment} />)
  fireEvent.click(screen.getByRole("button", { name: "Update now" }))
  expect((await screen.findByRole("alert")).textContent).toContain("Running containers were not stopped")
  expect(gpuApi.installCuda).not.toHaveBeenCalled()
})

it("an old error cannot reinstall an already current runtime", async () => {
  vi.mocked(gpuApi.cudaStatus).mockResolvedValue(current)
  const updated=vi.fn()
  render(<CudaUpdateAction environment={environment} onUpdated={updated} />)
  fireEvent.click(screen.getByRole("button", { name: "Update now" }))
  await screen.findByRole("status")
  expect(gpuApi.installCuda).not.toHaveBeenCalled()
  expect(updated).toHaveBeenCalledOnce()
})

it("shows failures and never reports success for a failed or incomplete update", async () => {
  const updated=vi.fn()
  vi.mocked(gpuApi.installCuda).mockRejectedValueOnce(new Error("Payload verification failed"))
  render(<CudaUpdateAction environment={environment} onUpdated={updated} />)
  fireEvent.click(screen.getByRole("button", { name: "Update now" }))
  expect((await screen.findByRole("alert")).textContent).toContain("Payload verification failed")
  expect(updated).not.toHaveBeenCalled()
  vi.mocked(gpuApi.installCuda).mockResolvedValueOnce({ ...current, updateAvailable: true })
  fireEvent.click(screen.getByRole("button", { name: "Update now" }))
  await vi.waitFor(() => expect(screen.getByRole("alert").textContent).toContain("not ready yet"))
  expect(updated).not.toHaveBeenCalled()
})

it("only offers CUDA updates for CUDA update errors", () => {
  const {rerender}=render(<CudaUpdateAction environment={environment} error="Not enough memory" />)
  expect(screen.queryByRole("button")).toBeNull()
  rerender(<CudaUpdateAction environment={{...environment,provider:"yougoriOci"}} />)
  expect(screen.queryByRole("button")).toBeNull()
  rerender(<CudaUpdateAction environment={environment} error="[YOUGORI_CUDA_UPDATE_REQUIRED] Update needed" />)
  expect(screen.getByRole("button",{name:"Update now"})).toBeTruthy()
})

it("replaces the misleading Refresh storage action with Update now and retries storage after updating", async () => {
  vi.mocked(platformApi.getStorageAllocation).mockRejectedValueOnce(new Error(environment.lastError!)).mockResolvedValueOnce({capacityGb:40,physicalGb:5,maximumGb:100,limitEnforced:true,shared:false})
  render(<StorageAllocationEditor environment={{...environment,kind:"container",status:"stopped"}} otherContainersActive={false} />)
  fireEvent.click(await screen.findByRole("button",{name:"Update now"}))
  expect(screen.queryByRole("button",{name:"Refresh storage"})).toBeNull()
  await screen.findByRole("slider",{name:"Storage limit"})
  expect(gpuApi.installCuda).toHaveBeenCalledWith("D:\\")
  expect(platformApi.getStorageAllocation).toHaveBeenCalledTimes(2)
})
