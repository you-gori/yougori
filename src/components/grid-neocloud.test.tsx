// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { GridRentedGpus } from "./grid-neocloud"
import { gridApi, type GridRentedGpus as Rented } from "@/api/grid-api"
import { toastManager } from "@/components/ui/toast"

vi.mock("@/components/ui/toast", () => ({ toastManager: { add: vi.fn() } }))
vi.mock("@/api/grid-api", () => ({
  gridApi: { rentedGpus: vi.fn(), addRentedGpu: vi.fn(), removeRentedGpu: vi.fn(), stopRentedGpus: vi.fn() },
}))

const serving = { environmentId: "env-a", memberId: "member-a", name: "Pod A", gpu: "NVIDIA RTX 4090", gpuCount: 1, hourlyUsd: 0.69, podState: "Running", state: "available", reason: "Serving acme/model on NVIDIA RTX 4090", model: "acme/model", jobs: 3 }
const stopped = { environmentId: "env-b", memberId: "member-b", name: "Pod B", gpu: "NVIDIA A100", gpuCount: 2, hourlyUsd: 3.2, podState: "Stopped", state: "stopped", reason: "Stopped in NeoCloud. Start it there to serve the grid again.", model: "acme/model", jobs: 0 }
const free = { environmentId: "env-c", name: "Pod C", gpu: "NVIDIA L40S", gpuCount: 1, hourlyUsd: 0.86, podState: "Running" }

const rented = (over: Partial<Rented> = {}): Rented => ({ hosting: true, max: 8, hourlyUsd: 0.69, members: [serving, stopped], candidates: [free], notice: null, notices: [], ...over })

beforeEach(() => {
  vi.mocked(gridApi.rentedGpus).mockResolvedValue(rented())
  vi.mocked(gridApi.addRentedGpu).mockResolvedValue({})
  vi.mocked(gridApi.removeRentedGpu).mockResolvedValue({})
  vi.mocked(gridApi.stopRentedGpus).mockResolvedValue({})
})
afterEach(() => { cleanup(); vi.resetAllMocks() })

const run = vi.fn(async (_job: string, work: () => Promise<unknown>) => { await work(); return true })

it("shows what each rented GPU costs and does, and a stopped pod never as working", async () => {
  render(<GridRentedGpus run={run} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  expect(section).toHaveTextContent("NeoCloud · 2 of 8 · $0.69/h while powered on")
  expect(section).toHaveTextContent("Pod A")
  expect(section).toHaveTextContent("NVIDIA RTX 4090 · $0.69/h · Serving · acme/model · 3 jobs")
  // The stopped pod reads as stopped, with what to do next, and never as serving.
  expect(section).toHaveTextContent("2 × NVIDIA A100 · $3.20/h · Stopped")
  expect(section).toHaveTextContent("Start it there to serve the grid again.")
  expect(section).not.toHaveTextContent("NVIDIA A100 · $3.20/h · Serving")
})

it("adds a rented pod, removes one with its pod stopped, and stops them all", async () => {
  render(<GridRentedGpus run={run} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  expect(within(section).getByRole("combobox", { name: "Rented GPU pod to add" })).toHaveValue("env-c")
  fireEvent.click(within(section).getByRole("button", { name: "Add to grid" }))
  await waitFor(() => expect(gridApi.addRentedGpu).toHaveBeenCalledWith("env-c"))
  fireEvent.click(within(section).getAllByRole("button", { name: "Remove and stop" })[1]!)
  await waitFor(() => expect(gridApi.removeRentedGpu).toHaveBeenCalledWith("env-b"))
  fireEvent.click(within(section).getByRole("button", { name: "Stop all rented GPUs" }))
  await waitFor(() => expect(gridApi.stopRentedGpus).toHaveBeenCalled())
})

it("says what the engine said about a stop, never a fixed 'stopped'", async () => {
  const pending = "The pod left the grid. The stop was sent; NeoCloud shows it stopping, and Yougori checks it again shortly. Its disk stays in NeoCloud until you delete it there."
  vi.mocked(gridApi.removeRentedGpu).mockResolvedValue({ message: pending })
  render(<GridRentedGpus run={run} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  fireEvent.click(within(section).getAllByRole("button", { name: "Remove and stop" })[0]!)
  await waitFor(() => expect(toastManager.add).toHaveBeenCalledWith(expect.objectContaining({ title: pending })))
  // The page is handed no fixed success text of its own to show beside it.
  expect(run).toHaveBeenLastCalledWith("Removing Pod A", expect.any(Function))
})

it("never reports a pod that could not be stopped as stopped", async () => {
  vi.mocked(gridApi.stopRentedGpus).mockResolvedValue({ warning: "Some rented GPUs could not be stopped; stop them in NeoCloud to end their billing: Pod A" })
  const failed: string[] = []
  const careful = vi.fn(async (_job: string, work: () => Promise<unknown>) => {
    try { await work(); return true } catch (reason) { failed.push(reason instanceof Error ? reason.message : String(reason)); return false }
  })
  render(<GridRentedGpus run={careful} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  fireEvent.click(within(section).getByRole("button", { name: "Stop all rented GPUs" }))
  await waitFor(() => expect(failed).toEqual(["Some rented GPUs could not be stopped; stop them in NeoCloud to end their billing: Pod A"]))
})

it("offers no more pods once the grid has its eight, and says why", async () => {
  const eight = Array.from({ length: 8 }, (_, at) => ({ ...serving, environmentId: `env-${at}`, name: `Pod ${at}` }))
  vi.mocked(gridApi.rentedGpus).mockResolvedValue(rented({ members: eight }))
  render(<GridRentedGpus run={run} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  expect(section).toHaveTextContent("8 of 8")
  expect(within(section).queryByRole("button", { name: "Add to grid" })).toBeNull()
  expect(section).toHaveTextContent("This grid has its 8 rented GPUs; remove one to add another.")
})

it("says where to rent one when no pod is free, and shows nothing off the hub", async () => {
  vi.mocked(gridApi.rentedGpus).mockResolvedValue(rented({ members: [], candidates: [], hourlyUsd: 0 }))
  const { unmount } = render(<GridRentedGpus run={run} />)
  expect(await screen.findByRole("region", { name: "Rented GPUs" })).toHaveTextContent("Rent one under Sandboxes, New environment, Neocloud")
  expect(screen.queryByRole("button", { name: "Stop all rented GPUs" })).toBeNull()
  unmount()
  vi.mocked(gridApi.rentedGpus).mockResolvedValue(rented({ hosting: false, members: [] }))
  render(<GridRentedGpus run={run} />)
  await waitFor(() => expect(gridApi.rentedGpus).toHaveBeenCalled())
  expect(screen.queryByRole("region", { name: "Rented GPUs" })).toBeNull()
})

it("keeps listed pods in view while no grid runs here, to remove, and offers none to add", async () => {
  vi.mocked(gridApi.rentedGpus).mockResolvedValue(rented({ hosting: false, members: [stopped], hourlyUsd: 0, notice: "No grid runs on this computer, so its rented GPUs were stopped." }))
  render(<GridRentedGpus run={run} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  expect(section).toHaveTextContent("No grid runs on this computer, so its rented GPUs were stopped.")
  expect(section).toHaveTextContent("2 × NVIDIA A100 · $3.20/h · Stopped")
  expect(within(section).queryByRole("button", { name: "Add to grid" })).toBeNull()
  fireEvent.click(within(section).getByRole("button", { name: "Remove and stop" }))
  await waitFor(() => expect(gridApi.removeRentedGpu).toHaveBeenCalledWith("env-b"))
})

it("says how each stop went, and a pod still being stopped never reads as stopped", async () => {
  const stopping = { ...serving, state: "stopping", reason: "Yougori is stopping this pod and tries again until NeoCloud confirms it. To serve the grid again, start it in NeoCloud once it has stopped." }
  const notices = [
    { at: 1, text: "Pod A, the rented GPU of your Neo Grid, could not be stopped (timeout). Stop it in NeoCloud to end its billing; Yougori keeps trying.", warning: true },
    { at: 2, text: "Pod B, the rented GPU of your Neo Grid, was stopped, so it is no longer billed. Start it in NeoCloud if you need it again.", warning: false },
  ]
  vi.mocked(gridApi.rentedGpus).mockResolvedValue(rented({ members: [stopping], notices }))
  render(<GridRentedGpus run={run} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  expect(within(section).getByRole("alert")).toHaveTextContent("could not be stopped (timeout)")
  expect(section).toHaveTextContent("was stopped, so it is no longer billed")
  expect(section).toHaveTextContent("NVIDIA RTX 4090 · $0.69/h · Stopping")
  expect(section).not.toHaveTextContent("$0.69/h · Stopped")
  // It may still be billing, so Stop all stays within reach.
  expect(within(section).getByRole("button", { name: "Stop all rented GPUs" })).toBeInTheDocument()
})

it("never gives a total that leaves out a running pod with no recorded price", async () => {
  const unpriced = { ...serving, environmentId: "env-d", name: "Pod D", hourlyUsd: 0 }
  vi.mocked(gridApi.rentedGpus).mockResolvedValue(rented({ members: [serving, unpriced], hourlyUsd: 0.69, unpriced: 1 }))
  render(<GridRentedGpus run={run} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  expect(section).toHaveTextContent("NeoCloud · 2 of 8 · at least $0.69/h while powered on")
  expect(section).toHaveTextContent("2 powered on · at least $0.69/h together")
  expect(section).toHaveTextContent("NVIDIA RTX 4090 · price unknown · Serving")
})

it("counts a pod NeoCloud has yet to check as billing, so Stop all reaches it", async () => {
  const unchecked = { ...stopped, podState: "Needs inspection", state: "starting", reason: "Starting in NeoCloud. It takes the grid's work once it runs." }
  vi.mocked(gridApi.rentedGpus).mockResolvedValue(rented({ members: [unchecked] }))
  render(<GridRentedGpus run={run} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  expect(within(section).getByRole("button", { name: "Stop all rented GPUs" })).toBeInTheDocument()
})
