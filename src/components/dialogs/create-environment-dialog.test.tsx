// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { CreateEnvironmentDialog } from "./create-environment-dialog"
import { gpuApi } from "@/api/gpu-api"
import { platformApi } from "@/api/platform-api"
import { defaultOciImage } from "@/data/oci-images"
import { runpodApi } from "@/api/runpod-api"

const create = vi.hoisted(() => vi.fn())
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ createEnvironment: create, state: { environments: [], host: { totalCpu: 8, totalMemoryGb: 16 } } }) }))
vi.mock("@/api/runpod-api", async importOriginal => ({ ...await importOriginal<typeof import("@/api/runpod-api")>(), runpodApi: { status: vi.fn(), connect: vi.fn(), catalog: vi.fn(), resources: vi.fn() } }))
vi.mock("@/components/host-terminal-canvas", () => ({ HostTerminalCanvas: () => <div /> }))
vi.mock("@/api/gpu-api", () => ({ gpuApi: { cudaStatus: vi.fn(), installCuda: vi.fn() } }))
vi.mock("@/api/platform-api", () => ({ platformApi: { getStorageAllocation: vi.fn() } }))
// Resource drag gestures have their own tests; keep these tests focused on
// category selection, compatibility, and the submitted native request.
vi.mock("@/components/dialogs/creation-resource-sliders", () => ({ CreationResourceSliders: () => null }))

beforeEach(() => {
  vi.stubGlobal("PointerEvent", MouseEvent)
  vi.resetAllMocks()
  create.mockResolvedValue(undefined)
  vi.mocked(runpodApi.status).mockResolvedValue({ installed: true, connected: false, message: "Not signed in" })
  vi.mocked(gpuApi.cudaStatus).mockResolvedValue({ supported: true, installed: true, running: false, detail: "Ready" })
  vi.mocked(platformApi.getStorageAllocation).mockResolvedValue({ capacityGb: 6, maximumGb: 100 } as Awaited<ReturnType<typeof platformApi.getStorageAllocation>>)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it("keeps creation choices focused on environments and imports", async () => {
  render(<CreateEnvironmentDialog open onOpenChange={() => {}} />)
  await screen.findByRole("radio", { name: "Container" })
  expect(screen.getByRole("radio", { name: "Cloud environment" })).toBeTruthy()
  expect(screen.getByRole("radio", { name: "Neocloud" })).toBeTruthy()
  expect(screen.getByRole("radio", { name: "Load local backup" })).toBeTruthy()
  expect(screen.queryByRole("radio", { name: "Deploy to cloud" })).toBeNull()
})

it("opens RunPod with a simple account connection first", async () => {
  render(<CreateEnvironmentDialog open onOpenChange={() => {}} />)
  fireEvent.click(await screen.findByRole("radio", { name: "Neocloud" }))
  await screen.findByRole("heading", { name: "Rent GPUs in the cloud" })
  expect(screen.queryByText("Prime Intellect")).toBeNull()
  expect((screen.getByRole("button", { name: "Connect" }) as HTMLButtonElement).disabled).toBe(true)
})

it("creates a GPU container from the Container GPU switch with Internet on and no PC folder access", async () => {
  render(<CreateEnvironmentDialog open onOpenChange={() => {}} />)
  expect(screen.queryByRole("radio", { name: "GPU" })).toBeNull()
  fireEvent.click(await screen.findByRole("switch", { name: "GPU access" }))
  await screen.findByText("Installed")
  expect(screen.queryByRole("group", { name: "Container engine" })).toBeNull()
  fireEvent.change(screen.getByRole("textbox", { name: "Name" }), { target: { value: "AI workspace" } })
  fireEvent.click(screen.getByRole("button", { name: "Create environment" }))
  await waitFor(() => expect(create).toHaveBeenCalledOnce())
  expect(create).toHaveBeenCalledWith(expect.objectContaining({ kind: "container", provider: "yougoriCuda", runtime: "docker.io/library/ubuntu:24.04", gpuAccess: true, networkAccess: true, storageGb: 20 }))
  expect(create.mock.calls[0]![0]).not.toHaveProperty("shares")
})

it("can create offline without changing the default for the next environment", async () => {
  const view = render(<CreateEnvironmentDialog open onOpenChange={() => {}} />)
  const internet = await screen.findByRole("switch", { name: "Internet access" })
  expect(internet.getAttribute("aria-checked")).toBe("true")
  fireEvent.click(internet)
  fireEvent.change(screen.getByRole("textbox", { name: "Name" }), { target: { value: "Offline workspace" } })
  fireEvent.click(screen.getByRole("button", { name: "Create environment" }))
  await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({ networkAccess: false })))
  view.rerender(<CreateEnvironmentDialog open={false} onOpenChange={() => {}} />)
  view.rerender(<CreateEnvironmentDialog open onOpenChange={() => {}} />)
  await waitFor(() => expect(screen.getByRole("switch", { name: "Internet access" }).getAttribute("aria-checked")).toBe("true"))
})

it.each([false, true])("offers 1 GB through the available maximum with GPU access %s", async gpuEnabled => {
  render(<CreateEnvironmentDialog open onOpenChange={() => {}} />)
  if (gpuEnabled) { fireEvent.click(await screen.findByRole("switch", { name: "GPU access" })); await screen.findByText("Installed") }
  const slider = await screen.findByRole("slider", { name: "Storage limit" })
  expect(slider.getAttribute("min")).toBe("1")
  expect(slider.getAttribute("max")).toBe("100")
  expect(screen.getByText(/Minimum 1 GB/)).toBeTruthy()
  fireEvent.change(screen.getByRole("spinbutton", { name: "Storage size in GB" }), { target: { value: "1" } })
  fireEvent.change(screen.getByRole("textbox", { name: "Name" }), { target: { value: `${gpuEnabled ? "GPU" : "Container"} minimum` } })
  fireEvent.click(screen.getByRole("button", { name: "Create environment" }))
  await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({ storageGb: 1 })))
})

it("does not leak GPU permission or image selection back into standard containers", async () => {
  render(<CreateEnvironmentDialog open onOpenChange={() => {}} />)
  fireEvent.click(await screen.findByRole("switch", { name: "GPU access" }))
  await screen.findByText("Installed")
  fireEvent.click(screen.getByRole("switch", { name: "GPU access" }))
  await waitFor(() => expect(screen.queryByText("Loading storage capacity…")).toBeNull())
  fireEvent.change(screen.getByRole("textbox", { name: "Name" }), { target: { value: "Standard workspace" } })
  fireEvent.click(screen.getByRole("button", { name: "Create environment" }))
  await waitFor(() => expect(create).toHaveBeenCalledOnce())
  expect(create).toHaveBeenCalledWith(expect.objectContaining({ kind: "container", provider: "yougoriOci", runtime: defaultOciImage.value, gpuAccess: false, networkAccess: true }))
})

it("blocks unsupported computers from creating GPU environments", async () => {
  vi.mocked(gpuApi.cudaStatus).mockResolvedValue({ supported: false, installed: true, running: false, detail: "No compatible NVIDIA GPU" })
  render(<CreateEnvironmentDialog open onOpenChange={() => {}} />)
  fireEvent.click(await screen.findByRole("switch", { name: "GPU access" }))
  await screen.findByText("No compatible NVIDIA GPU")
  expect((screen.getByRole("button", { name: "Create environment" }) as HTMLButtonElement).disabled).toBe(true)
  fireEvent.click(screen.getByRole("button", { name: "Create environment" }))
  expect(create).not.toHaveBeenCalled()
})
