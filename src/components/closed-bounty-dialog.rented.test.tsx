// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ClosedBountyDialog } from "./closed-bounty-dialog"
import { bountyApi, type PrivatePreview } from "@/api/bounty-api"
import { swarmApi } from "@/api/swarm-api"

vi.mock("@/api/bounty-api", () => ({ bountyApi: { suggestedAddress: vi.fn(), choosePath: vi.fn(), inspect: vi.fn(), host: vi.fn(), start: vi.fn(), discard: vi.fn() } }))
vi.mock("@/api/swarm-api", () => ({
  noRentedGpus: { workers: [], candidates: [], hourlyUsd: 0, notices: [] },
  swarmApi: { rentedGpus: vi.fn() },
}))
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn().mockResolvedValue("C:/fixture") }))

const target = { kind: "source" as const, setupCommand: "", startCommand: "", testCommand: "", port: 3000, healthPath: "/", installNetwork: false, baseUrl: "" }
const preview = (rentedGpu?: boolean): PrivatePreview => ({ ticket: "preview-fixture", policy: { title: "Checkout review", objective: "Test fixture", authorization: "We own this fixture", sourceRevision: "rev", termsDigest: "digest", target, ...(rentedGpu ? { rentedGpu } : {}) } } as PrivatePreview)
const permission = () => screen.getByRole("checkbox", { name: /GPU rented from an outside provider/ })

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(bountyApi.suggestedAddress).mockResolvedValue("192.168.1.20")
  vi.mocked(bountyApi.choosePath).mockResolvedValue("C:/fixture")
  vi.mocked(bountyApi.inspect).mockResolvedValue({ importId: "import-fixture", name: "Website", fileCount: 1, bytes: 12, files: ["index.html"], excluded: [], suggestedTarget: target })
  vi.mocked(bountyApi.host).mockResolvedValue({ preview: preview(true), name: "Fixture", address: "127.0.0.1", invite: "invite", bounty: { title: "Website" }, members: [] } as unknown as Awaited<ReturnType<typeof bountyApi.host>>)
  vi.mocked(bountyApi.start).mockResolvedValue({ worker: { id: "worker-fixture" } } as Awaited<ReturnType<typeof bountyApi.start>>)
  vi.mocked(swarmApi.rentedGpus).mockResolvedValue({ workers: [], candidates: [{ environmentId: "pod-d", name: "Pod D", gpu: "NVIDIA L40S", gpuCount: 1, hourlyUsd: 0.86, podState: "Running" }], hourlyUsd: 0, notices: [] })
})
afterEach(cleanup)

it("asks the host every time with the box off, even after it was ticked and the dialog closed", () => {
  const props = { onOpenChange: vi.fn(), onReady: vi.fn() }
  const { rerender } = render(<ClosedBountyDialog open {...props} />)
  expect(permission()).not.toBeChecked()
  fireEvent.click(permission())
  expect(permission()).toBeChecked()
  rerender(<ClosedBountyDialog open={false} {...props} />)
  rerender(<ClosedBountyDialog open {...props} />)
  expect(permission()).not.toBeChecked()
})

it("sends the host's answer with the bounty, and nothing when the box is left off", async () => {
  render(<ClosedBountyDialog open onOpenChange={vi.fn()} onReady={vi.fn()} />)
  fireEvent.click(screen.getByRole("button", { name: "Choose folder" }))
  await screen.findByText(/Website · 1 files/)
  fireEvent.change(screen.getByLabelText("Authorized scope and test accounts"), { target: { value: "We own this fixture" } })
  fireEvent.click(screen.getByLabelText(/I authorize testing/))
  fireEvent.click(permission())
  fireEvent.click(screen.getByRole("button", { name: "Host bounty" }))
  await waitFor(() => expect(bountyApi.host).toHaveBeenCalledWith(expect.objectContaining({ rentedGpu: true, confirmed: true })))
})

it("starts a worker on a rented GPU the host allowed, without the local storage check", async () => {
  const close = vi.fn()
  render(<ClosedBountyDialog open join connection={preview(true)} onOpenChange={close} onReady={vi.fn()} />)
  fireEvent.click(screen.getByRole("radio", { name: /GPU you rented in NeoCloud/ }))
  expect(await screen.findByRole("combobox", { name: "Rented GPU" })).toHaveValue("pod-d")
  // The local model field and the local storage fields are not this worker's.
  expect(screen.queryByLabelText("Hugging Face GGUF model")).toBeNull()
  expect(screen.queryByLabelText("Model storage drive")).toBeNull()
  fireEvent.click(screen.getByLabelText(/I approve this project/))
  fireEvent.click(screen.getByRole("button", { name: "Start worker" }))
  await waitFor(() => expect(bountyApi.start).toHaveBeenCalledWith(preview(true), expect.objectContaining({
    model: "hf.co/mlabonne/Qwen3-8B-abliterated", rentedGpu: "pod-d", resources: { cpu: 4, memoryGb: 8 },
  }), 60, "review"))
  await waitFor(() => expect(close).toHaveBeenCalledWith(false))
})

it("says which bounty keeps its code on this computer, and offers no rented GPU", () => {
  render(<ClosedBountyDialog open join connection={preview()} onOpenChange={vi.fn()} onReady={vi.fn()} />)
  expect(screen.getByText("“Checkout review” doesn't allow its code on a rented GPU, so the model runs on this computer.")).toBeInTheDocument()
  expect(screen.queryByRole("radio")).toBeNull()
  expect(screen.getByLabelText("Hugging Face GGUF model")).toBeInTheDocument()
  expect(swarmApi.rentedGpus).not.toHaveBeenCalled()
})
