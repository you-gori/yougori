// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, expect, it, vi } from "vitest"
import type { CombinePreview } from "@/api/sandbox-vm-api"

const api = vi.hoisted(() => ({ combinePreview: vi.fn(), combineStart: vi.fn(), combineFinish: vi.fn() }))
vi.mock("@/api/sandbox-vm-api", async importOriginal => ({
  ...await importOriginal<typeof import("@/api/sandbox-vm-api")>(), sandboxVmApi: api,
}))
import { CombineSandboxesDialog } from "./combine-dialog"

afterEach(() => { cleanup(); Object.values(api).forEach(fn => fn.mockReset()) })

const preview = (undecided: number): CombinePreview => ({
  compatible: true, reasons: [], digest: "d".repeat(64),
  sources: [
    { sandbox: "vm-a", os: { ID: "alpine", PRETTY_NAME: "Alpine Linux v3.24", machine: "x86_64" }, image: null, memoryBytes: 2 ** 30, cpu: 1, workspace: { folder: "C:/a", files: 2, bytes: 10 } },
    { sandbox: "vm-b", os: { ID: "alpine", PRETTY_NAME: "Alpine Linux v3.24", machine: "x86_64" }, image: null, memoryBytes: 2 ** 30, cpu: 2, workspace: null },
  ],
  combined: { params: { memoryGb: 2, cpu: 3 }, layout: "separate", workspace: [] },
  conflicts: [{ kind: "publish", key: "publish:web", decision: undecided ? null : "second" }],
  undecidedConflicts: undecided,
  capacity: { fits: true, requiredBytes: 2 ** 31, releasedByOriginalsBytes: 2 ** 31 },
  permissions: { lastingGrants: [{ grant: "g1", path: "C:/Projects", mode: "read", folder: true, adopt: false }] },
  notCarried: ["running processes"], transition: "Both stop, one boots.", trust: "Both share one kernel.",
})

it("shows the summed allocation and combines only after every conflict is decided, carrying ticked grants", async () => {
  const user = userEvent.setup()
  api.combinePreview.mockImplementation((_a: string, _b: string, decisions: { keep: Record<string, string> }) =>
    Promise.resolve(preview(decisions.keep["publish:web"] ? 0 : 1)))
  api.combineStart.mockResolvedValue({ operation: "combine-1", state: "healthy", combined: "vm-c" })
  render(<CombineSandboxesDialog first="vm-a" second="vm-b" open onOpenChange={() => {}} />)
  expect(await screen.findByText(/3 vCPU, 2.00 GiB/)).toBeVisible()
  const combine = screen.getByRole("button", { name: "Combine" })
  expect(combine).toBeDisabled()
  await user.click(screen.getByRole("radio", { name: "Keep vm-b's" }))
  await user.click(screen.getByRole("checkbox", { name: /C:\/Projects/ }))
  await waitFor(() => expect(screen.getByRole("button", { name: "Combine" })).toBeEnabled())
  await user.click(screen.getByRole("button", { name: "Combine" }))
  expect(api.combineStart).toHaveBeenCalledWith("vm-a", "vm-b", "d".repeat(64), expect.objectContaining({
    keep: { "publish:web": "second" }, adopt: ["g1"], layout: "separate",
  }))
  expect(await screen.findByText(/Combined into vm-c/)).toBeVisible()
  api.combineFinish.mockResolvedValue({ operation: "combine-1", state: "finished" })
  await user.click(screen.getByRole("button", { name: "Keep the originals' workspaces" }))
  expect(api.combineFinish).toHaveBeenCalledWith("combine-1", "keep")
})

it("never offers to combine sandboxes the preview found incompatible", async () => {
  api.combinePreview.mockResolvedValue({ ...preview(0), compatible: false, reasons: ["ID differs"] })
  render(<CombineSandboxesDialog first="vm-a" second="vm-b" open onOpenChange={() => {}} />)
  expect(await screen.findByRole("alert")).toHaveTextContent("ID differs")
  expect(screen.getByRole("button", { name: "Combine" })).toBeDisabled()
})
