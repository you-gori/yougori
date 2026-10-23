// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { ClosedBountyDialog } from "./closed-bounty-dialog"
import { bountyApi } from "@/api/bounty-api"

const edition = vi.hoisted(() => ({ liveTargets: false }))
vi.mock("@/lib/distribution", () => ({ get LIVE_TARGETS() { return edition.liveTargets } }))
vi.mock("@/api/bounty-api", () => ({ bountyApi: {
  suggestedAddress: vi.fn().mockResolvedValue(null), choosePath: vi.fn().mockResolvedValue("fixture"),
  inspect: vi.fn(), host: vi.fn(), discard: vi.fn(),
} }))
afterEach(() => { cleanup(); vi.clearAllMocks() })

it("keeps live targets available in the private edition", () => {
  edition.liveTargets = true
  render(<ClosedBountyDialog open onOpenChange={vi.fn()} onReady={vi.fn()} />)
  expect(screen.getByRole("option", { name: /Live URL/ })).toBeTruthy()
  fireEvent.change(screen.getByLabelText("What are you testing?"), { target: { value: "url" } })
  expect(screen.getByLabelText("Live service URL")).toBeTruthy()
})

it("removes live targets in the public edition and rejects a URL recipe returned by an import", async () => {
  edition.liveTargets = false
  vi.mocked(bountyApi.inspect).mockResolvedValue({
    importId: "fixture", name: "Old private recipe", fileCount: 1, bytes: 1, files: ["a.js"], excluded: [],
    suggestedTarget: { kind: "url", baseUrl: "https://fixture.invalid", setupCommand: "", startCommand: "", testCommand: "", port: 3000, healthPath: "/", installNetwork: false },
  })
  render(<ClosedBountyDialog open onOpenChange={vi.fn()} onReady={vi.fn()} />)
  expect(screen.queryByRole("option", { name: /Live URL/ })).toBeNull()
  expect(screen.queryByLabelText("Live service URL")).toBeNull()
  fireEvent.click(screen.getByRole("button", { name: "Choose folder" }))
  await screen.findByText(/Old private recipe · 1 files/)
  fireEvent.change(screen.getByLabelText("Authorized scope and test accounts"), { target: { value: "Fixture scope" } })
  fireEvent.click(screen.getByLabelText(/I authorize testing/))
  expect((screen.getByRole("button", { name: "Host bounty" }) as HTMLButtonElement).disabled).toBe(true)
  expect(bountyApi.host).not.toHaveBeenCalled()
})
