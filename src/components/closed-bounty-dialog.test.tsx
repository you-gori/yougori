// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ClosedBountyDialog } from "./closed-bounty-dialog"
import { bountyApi } from "@/api/bounty-api"

vi.mock("@/api/bounty-api", () => ({ bountyApi: { suggestedAddress: vi.fn(), choosePath: vi.fn(), inspect: vi.fn(), host: vi.fn(), start: vi.fn(), discard: vi.fn() } }))
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn().mockResolvedValue("C:/fixture") }))
const target = { kind: "web" as const, setupCommand: "", startCommand: "python3 -m http.server 3000", testCommand: "", port: 3000, healthPath: "/", installNetwork: false, baseUrl: "" }
const preview = { ticket: "preview-fixture", policy: { title: "Website", objective: "Test fixture", authorization: "We own this fixture", sourceRevision: "rev", termsDigest: "digest", target } }
beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(bountyApi.suggestedAddress).mockResolvedValue("192.168.1.20")
  vi.mocked(bountyApi.choosePath).mockResolvedValue("C:/fixture")
  vi.mocked(bountyApi.inspect).mockResolvedValue({ importId: "import-fixture", name: "Website", fileCount: 1, bytes: 12, files: ["index.html"], excluded: [], suggestedTarget: target })
  vi.mocked(bountyApi.host).mockResolvedValue({ preview, name: "Fixture", address: "127.0.0.1", invite: "invite", bounty: { title: "Website" }, members: [] })
  vi.mocked(bountyApi.start).mockResolvedValue({ worker: { id: "worker-fixture" } } as Awaited<ReturnType<typeof bountyApi.start>>)
})
afterEach(cleanup)
it("imports a real project, reviews its recipe and creates a private worker without practiceStart", async () => {
  const close = vi.fn()
  render(<ClosedBountyDialog open onOpenChange={close} onReady={vi.fn()} />)
  fireEvent.click(screen.getByRole("button", { name: "Choose folder" }))
  await screen.findByText(/Website · 1 files/)
  expect((screen.getByLabelText("Start command") as HTMLInputElement).value).toBe(target.startCommand)
  fireEvent.change(screen.getByLabelText("Authorized scope and test accounts"), { target: { value: "We own this fixture" } })
  fireEvent.click(screen.getByLabelText(/I authorize testing/))
  fireEvent.click(screen.getByRole("button", { name: "Host bounty" }))
  await screen.findByLabelText("Hugging Face GGUF model")
  expect(bountyApi.host).toHaveBeenCalledWith(expect.objectContaining({ importId: "import-fixture", visibility: "local", target, confirmed: true }))
  fireEvent.change(screen.getByLabelText("Hugging Face GGUF model"), { target: { value: "fixture/model-GGUF" } })
  fireEvent.click(screen.getByLabelText(/I approve this project/))
  fireEvent.click(screen.getByRole("button", { name: "Start worker" }))
  await waitFor(() => expect(bountyApi.start).toHaveBeenCalledWith(preview, expect.objectContaining({ model: "hf.co/fixture/model-GGUF" }), 60, "review"))
  await waitFor(() => expect(close).toHaveBeenCalledWith(false))
})
