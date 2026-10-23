// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ClosedBountyDialog } from "./closed-bounty-dialog"
import { bountyApi } from "@/api/bounty-api"
import { modelsApi } from "@/api/projects-api"

// A computer with a nearly full system drive and a roomy data drive, so the same model fits one
// and not the other. This is exactly the case that used to fail only after the worker was made.
vi.mock("@/context/platform-context", () => ({
  usePlatformOptional: () => ({
    state: {
      host: {
        storageDrives: [
          { path: "C:\\", name: "System", fileSystem: "NTFS", totalGb: 500, freeGb: 8, readOnly: false, removable: false },
          { path: "D:\\", name: "Data", fileSystem: "NTFS", totalGb: 2000, freeGb: 900, readOnly: false, removable: false },
        ],
      },
    },
  }),
}))

// The model's real size, learned by the same preflight the worker runs, without making a worker.
vi.mock("@/api/projects-api", () => ({
  modelsApi: { preflight: vi.fn().mockResolvedValue({ supported: true, resources: { storageGbRecommended: 28, estimateOnly: false } }) },
}))

vi.mock("@/api/bounty-api", () => ({ bountyApi: { suggestedAddress: vi.fn().mockResolvedValue(""), start: vi.fn() } }))

const target = { kind: "web" as const, setupCommand: "", startCommand: "", testCommand: "", port: 3000, healthPath: "/", installNetwork: false, baseUrl: "" }
const connection = { ticket: "t", policy: { title: "Website", objective: "o", authorization: "a", sourceRevision: "r", termsDigest: "d", target } } as never

beforeEach(() => vi.clearAllMocks())
afterEach(cleanup)

it("lets a person pick the model's drive and refuses a model that will not fit before any worker is made", async () => {
  render(<ClosedBountyDialog open onOpenChange={vi.fn()} onReady={vi.fn()} connection={connection} />)

  // Both drives are offered, each with its free space shown.
  const driveSelect = await screen.findByLabelText("Model storage drive") as HTMLSelectElement
  expect(Array.from(driveSelect.options).map(option => option.textContent)).toEqual([
    expect.stringContaining("8 GB free"),
    expect.stringContaining("900 GB free"),
  ])
  // The roomiest drive is chosen first, so the first offer is one that could fit.
  expect(driveSelect.value).toBe("D:\\")

  // Approve the scope and name a model. Naming it asks the model its size before anything is
  // created, and raises the storage to it.
  fireEvent.click(screen.getByRole("checkbox"))
  fireEvent.change(screen.getByLabelText("Hugging Face GGUF model"), { target: { value: "huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF" } })
  // The check runs itself a moment after typing stops; no need to click away.
  await screen.findByText(/needs about 28 GB/)
  expect((screen.getByLabelText("Model storage (GiB)") as HTMLInputElement).value).toBe("28")

  // On the roomy drive it fits and the worker may start. On the nearly full system drive it does
  // not, and that is said here, before any worker exists, with Start held back.
  expect((screen.getByRole("button", { name: "Start worker" }) as HTMLButtonElement).disabled).toBe(false)
  fireEvent.change(driveSelect, { target: { value: "C:\\" } })
  await waitFor(() => expect(screen.getByText(/needs about 28 GB but C: has 8 GB free/)).toBeTruthy())
  expect((screen.getByRole("button", { name: "Start worker" }) as HTMLButtonElement).disabled).toBe(true)
})

it("ignores an answer about a model the person has since replaced, however late it arrives", async () => {
  // The first model's check is slow and is still out when the person types a second model, whose
  // check answers at once. The slow answer then arrives last and must change nothing.
  let finishFirst: (value: unknown) => void = () => {}
  vi.mocked(modelsApi.preflight)
    .mockImplementationOnce(() => new Promise(resolve => { finishFirst = resolve }) as never)
    .mockResolvedValueOnce({ supported: true, resources: { storageGbRecommended: 14, estimateOnly: false } } as never)
  render(<ClosedBountyDialog open onOpenChange={vi.fn()} onReady={vi.fn()} connection={connection} />)
  const field = await screen.findByLabelText("Hugging Face GGUF model")

  fireEvent.change(field, { target: { value: "owner/Big-27B-GGUF" } })
  await waitFor(() => expect(modelsApi.preflight).toHaveBeenCalledTimes(1))
  fireEvent.change(field, { target: { value: "owner/Small-7B-GGUF" } })
  await screen.findByText(/needs about 14 GB/)

  await act(async () => { finishFirst({ supported: true, resources: { storageGbRecommended: 28, estimateOnly: false } }) })

  expect(screen.getByText(/needs about 14 GB/)).toBeTruthy()
  expect(screen.queryByText(/needs about 28 GB/)).toBeNull()
  // The storage field was never raised to the stale size, and no spinner is left behind.
  expect((screen.getByLabelText("Model storage (GiB)") as HTMLInputElement).value).toBe("24")
  expect(screen.queryByText(/Checking .* on Hugging Face/)).toBeNull()
})


it("sizes RAM from the model before starting and preserves an explicit larger budget", async () => {
  vi.mocked(modelsApi.preflight).mockResolvedValueOnce({ supported: true, resources: { storageGbRecommended: 28, workerMemoryGbRecommended: 32 } } as never)
  render(<ClosedBountyDialog open onOpenChange={vi.fn()} onReady={vi.fn()} connection={connection} />)
  fireEvent.change(screen.getByLabelText("Hugging Face GGUF model"), { target: { value: "fixture/27B-Q6" } })
  await screen.findByText(/28 GiB for the model and 4 GiB/)
  expect((screen.getByLabelText("Memory (GiB)") as HTMLInputElement).value).toBe("32")
  fireEvent.click(screen.getByRole("checkbox"))
  fireEvent.click(screen.getByRole("button", { name: "Start worker" }))
  await waitFor(() => expect(bountyApi.start).toHaveBeenCalledWith(connection, expect.objectContaining({ resources: expect.objectContaining({ memoryGb: 32 }) }), 60, "review"))
  fireEvent.change(screen.getByLabelText("Memory (GiB)"), { target: { value: "40" } })
  vi.mocked(modelsApi.preflight).mockResolvedValueOnce({ supported: true, resources: { storageGbRecommended: 20, workerMemoryGbRecommended: 24 } } as never)
  fireEvent.change(screen.getByLabelText("Hugging Face GGUF model"), { target: { value: "fixture/smaller" } })
  await screen.findByText(/needs about 20 GB/)
  expect((screen.getByLabelText("Memory (GiB)") as HTMLInputElement).value).toBe("40")
})

it("leaves unedited RAM automatic if Start is clicked before preflight returns", async () => {
  render(<ClosedBountyDialog open onOpenChange={vi.fn()} onReady={vi.fn()} connection={connection} />)
  fireEvent.change(screen.getByLabelText("Hugging Face GGUF model"), { target: { value: "fixture/unchecked" } })
  fireEvent.click(screen.getByRole("checkbox"))
  fireEvent.click(screen.getByRole("button", { name: "Start worker" }))
  await waitFor(() => expect(bountyApi.start).toHaveBeenCalledWith(connection, expect.objectContaining({ resources: expect.objectContaining({ memoryGb: undefined }) }), 60, "review"))
})
