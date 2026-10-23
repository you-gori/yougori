// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { useState } from "react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ModelPlacement, RentedGpuPermission, SwarmRentedGpus } from "./swarm-rented-gpu"
import { swarmApi, type SwarmRentedGpus as Rented, type SwarmRentedWorker } from "@/api/swarm-api"
import { placementProblem, placementSetup, RENTED_MODELS, type Placement } from "@/lib/rented-gpu"
import { toastManager } from "@/components/ui/toast"

vi.mock("@/components/ui/toast", () => ({ toastManager: { add: vi.fn() } }))
vi.mock("@/api/swarm-api", () => ({
  noRentedGpus: { workers: [], candidates: [], hourlyUsd: 0, notices: [] },
  swarmApi: { rentedGpus: vi.fn(), stopRentedGpu: vi.fn(), stopRentedGpus: vi.fn() },
}))

const working: SwarmRentedWorker = { workerId: "w1", workerName: "Night shift", workerState: "running", environmentId: "pod-a", name: "Pod A", gpu: "NVIDIA RTX 4090", gpuCount: 1, hourlyUsd: 0.69, podState: "Running", billing: true }
const paused: SwarmRentedWorker = { ...working, workerId: "w2", workerName: "Day shift", workerState: "paused", environmentId: "pod-b", name: "Pod B" }
const stopped: SwarmRentedWorker = { ...working, workerId: "w3", workerName: "Weekend", workerState: "paused", environmentId: "pod-c", name: "Pod C", podState: "Stopped", billing: false }
const free = { environmentId: "pod-d", name: "Pod D", gpu: "NVIDIA L40S", gpuCount: 1, hourlyUsd: 0.86, podState: "Running" }

const rented = (over: Partial<Rented> = {}): Rented => ({ workers: [working, paused, stopped], candidates: [free], hourlyUsd: 1.38, notices: [], ...over })
const run = vi.fn(async (_job: string, work: () => Promise<unknown>) => { await work(); return true })

beforeEach(() => {
  vi.mocked(swarmApi.rentedGpus).mockResolvedValue(rented())
  vi.mocked(swarmApi.stopRentedGpu).mockResolvedValue({ message: "stopped" })
  vi.mocked(swarmApi.stopRentedGpus).mockResolvedValue({ message: "stopped" })
})
afterEach(() => { cleanup(); vi.resetAllMocks() })

it("never gives a total that leaves out a running pod with no recorded price", async () => {
  const unpriced: SwarmRentedWorker = { ...working, workerId: "w4", workerName: "Late shift", environmentId: "pod-e", name: "Pod E", hourlyUsd: 0 }
  vi.mocked(swarmApi.rentedGpus).mockResolvedValue(rented({ workers: [working, unpriced], hourlyUsd: 0.69, unpriced: 1 }))
  render(<SwarmRentedGpus run={run} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  expect(section).toHaveTextContent("NeoCloud · 2 workers · at least $0.69/h while powered on")
  expect(section).toHaveTextContent("2 powered on · at least $0.69/h together")
})

it("says what each worker's rented GPU costs and does, and a paused worker's GPU is still billed", async () => {
  render(<SwarmRentedGpus run={run} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  expect(section).toHaveTextContent("NeoCloud · 3 workers · $1.38/h while powered on")
  expect(section).toHaveTextContent("Pod A · NVIDIA RTX 4090 · $0.69/h · running")
  expect(section).toHaveTextContent("Pod B · NVIDIA RTX 4090 still runs while Day shift is paused, and is billed at $0.69/h. Stop it if you are done for now.")
  // A stopped pod reads as stopped, with the person's next step, and offers no Stop.
  expect(section).toHaveTextContent("Pod C · NVIDIA RTX 4090 is Stopped in NeoCloud and not billed. Start it there, then choose Resume. Yougori never rents or starts a GPU for you.")
  expect(within(section).getAllByRole("button", { name: "Stop rented GPU" })).toHaveLength(2)
  fireEvent.click(within(section).getAllByRole("button", { name: "Stop rented GPU" })[1]!)
  await waitFor(() => expect(swarmApi.stopRentedGpu).toHaveBeenCalledWith("w2"))
  fireEvent.click(within(section).getByRole("button", { name: "Stop all rented GPUs" }))
  await waitFor(() => expect(swarmApi.stopRentedGpus).toHaveBeenCalled())
})

it("says what the engine said about a worker's stop, never a fixed 'stopped'", async () => {
  const pending = "The stop was sent; NeoCloud shows Pod A stopping. Yougori checks it again shortly. Night shift is paused."
  vi.mocked(swarmApi.stopRentedGpu).mockResolvedValue({ message: pending })
  render(<SwarmRentedGpus run={run} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  fireEvent.click(within(section).getAllByRole("button", { name: "Stop rented GPU" })[0]!)
  await waitFor(() => expect(toastManager.add).toHaveBeenCalledWith(expect.objectContaining({ title: pending })))
  expect(run).toHaveBeenLastCalledWith("Stopping Night shift's rented GPU", expect.any(Function))
})

it("never reports a rented GPU that could not be stopped as stopped", async () => {
  vi.mocked(swarmApi.stopRentedGpu).mockResolvedValue({ warning: "Pod A could not be stopped (timeout). Stop it in NeoCloud to end its billing." })
  const failed: string[] = []
  const careful = vi.fn(async (_job: string, work: () => Promise<unknown>) => {
    try { await work(); return true } catch (reason) { failed.push(reason instanceof Error ? reason.message : String(reason)); return false }
  })
  render(<SwarmRentedGpus run={careful} />)
  const section = await screen.findByRole("region", { name: "Rented GPUs" })
  fireEvent.click(within(section).getAllByRole("button", { name: "Stop rented GPU" })[0]!)
  await waitFor(() => expect(failed).toEqual(["Pod A could not be stopped (timeout). Stop it in NeoCloud to end its billing."]))
})

it("keeps a failed stop on the page, even after its worker is gone", async () => {
  vi.mocked(swarmApi.rentedGpus).mockResolvedValue(rented({ workers: [], hourlyUsd: 0, notices: [{ at: 1, text: "Pod A, the rented GPU of Night shift, could not be stopped (timeout). Stop it in NeoCloud to end its billing; Yougori keeps trying.", warning: true }] }))
  render(<SwarmRentedGpus run={run} />)
  expect(await screen.findByRole("alert")).toHaveTextContent("could not be stopped (timeout)")
  expect(screen.queryByRole("button", { name: "Stop all rented GPUs" })).toBeNull()
})

it("shows nothing when no worker uses a rented GPU", async () => {
  vi.mocked(swarmApi.rentedGpus).mockResolvedValue(rented({ workers: [], hourlyUsd: 0 }))
  render(<SwarmRentedGpus run={run} />)
  await waitFor(() => expect(swarmApi.rentedGpus).toHaveBeenCalled())
  expect(screen.queryByRole("region", { name: "Rented GPUs" })).toBeNull()
})

it("asks the host plainly, with nothing ticked", () => {
  const changed = vi.fn()
  render(<RentedGpuPermission checked={false} onChange={changed} />)
  const box = screen.getByRole("checkbox", { name: /GPU rented from an outside provider/ })
  expect(box).not.toBeChecked()
  fireEvent.click(box)
  expect(changed).toHaveBeenCalledWith(true)
})

it("says which bounty keeps its code off rented GPUs", () => {
  render(<ModelPlacement title="Acme checkout" allowed={false} value={null} onChange={vi.fn()} />)
  expect(screen.getByText("“Acme checkout” doesn't allow its code on a rented GPU, so the model runs on this computer.")).toBeInTheDocument()
  expect(screen.queryByRole("radio")).toBeNull()
  expect(swarmApi.rentedGpus).not.toHaveBeenCalled()
})

function Placing({ onPlaced }: { onPlaced(value: Placement | null): void }) {
  const [value, setValue] = useState<Placement | null>(null)
  return <ModelPlacement title="Acme" allowed value={value} onChange={next => { setValue(next); onPlaced(next) }} />
}

it("offers a running free pod and the models that call tools there", async () => {
  const placed = vi.fn()
  render(<Placing onPlaced={placed} />)
  const radios = await screen.findAllByRole("radio")
  expect(radios[0]).toBeChecked()
  await waitFor(() => expect(swarmApi.rentedGpus).toHaveBeenCalled())
  fireEvent.click(screen.getByRole("radio", { name: /GPU you rented in NeoCloud/ }))
  expect(placed).toHaveBeenLastCalledWith({ pod: "pod-d", model: RENTED_MODELS[0]!.id })
  expect(screen.getByRole("combobox", { name: "Rented GPU" })).toHaveValue("pod-d")
  expect(screen.getByText(/billed by RunPod at \$0\.86\/h while it runs/)).toBeInTheDocument()
  expect(screen.getByText(/only Qwen 2\.5, Qwen 3, Llama 3, gpt-oss and Gemma 4 models call tools there/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: /Qwen3 14B/ }))
  expect(placed).toHaveBeenLastCalledWith({ pod: "pod-d", model: "mlabonne/Qwen3-14B-abliterated" })
})

it("says where to rent one when no pod is free", async () => {
  vi.mocked(swarmApi.rentedGpus).mockResolvedValue(rented({ candidates: [] }))
  render(<Placing onPlaced={vi.fn()} />)
  await waitFor(() => expect(swarmApi.rentedGpus).toHaveBeenCalled())
  fireEvent.click(screen.getByRole("radio", { name: /GPU you rented in NeoCloud/ }))
  expect(await screen.findByText(/No rented GPU is running and free/)).toBeInTheDocument()
})

it("never reads a list it could not load as no rented GPU, and lets the person try again", async () => {
  vi.mocked(swarmApi.rentedGpus).mockRejectedValueOnce(new Error("The engine did not answer"))
  render(<Placing onPlaced={vi.fn()} />)
  await waitFor(() => expect(swarmApi.rentedGpus).toHaveBeenCalledTimes(1))
  fireEvent.click(screen.getByRole("radio", { name: /GPU you rented in NeoCloud/ }))
  expect(await screen.findByRole("alert")).toHaveTextContent("could not read your rented GPUs (The engine did not answer)")
  expect(screen.queryByText(/No rented GPU is running and free/)).toBeNull()
  fireEvent.click(screen.getByRole("button", { name: "Try again" }))
  expect(await screen.findByRole("combobox", { name: "Rented GPU" })).toHaveValue("pod-d")
})

it("names what is still missing and sends the model with its pod", () => {
  expect(placementProblem(null)).toBe("")
  expect(placementProblem({ pod: "", model: "a/b" })).toBe("Choose a running rented GPU, or run the model on this computer.")
  expect(placementProblem({ pod: "pod-d", model: " " })).toBe("Choose the model it runs.")
  expect(placementProblem({ pod: "pod-d", model: "a/b" })).toBe("")
  expect(placementSetup({ pod: "pod-d", model: "https://huggingface.co/mlabonne/Qwen3-8B-abliterated" })).toEqual({ model: "hf.co/mlabonne/Qwen3-8B-abliterated", rentedGpu: "pod-d" })
})
