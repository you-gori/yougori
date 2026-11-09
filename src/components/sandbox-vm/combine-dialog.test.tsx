// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { act, cleanup, render, screen, waitFor } from "@testing-library/react"
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
  }), expect.stringMatching(/^desktop-[A-Za-z0-9-]+$/))
  expect(await screen.findByText(/Combined into vm-c/)).toBeVisible()
  api.combineFinish.mockResolvedValue({ operation: "combine-1", state: "finished" })
  await user.click(screen.getByRole("button", { name: "Keep the originals' workspaces" }))
  expect(api.combineFinish).toHaveBeenCalledWith("combine-1", "keep")
})

it("asks the engine for one preview per set of decisions, not again every time an answer arrives", async () => {
  const user = userEvent.setup()
  api.combinePreview.mockImplementation((_a: string, _b: string, decisions: { keep: Record<string, string> }) =>
    Promise.resolve(preview(decisions.keep["publish:web"] ? 0 : 1)))
  render(<CombineSandboxesDialog first="vm-a" second="vm-b" open onOpenChange={() => {}} />)
  expect(await screen.findByText(/3 vCPU, 2.00 GiB/)).toBeVisible()
  // Each answer is a fresh object; it must not count as a change of the decisions.
  await act(() => new Promise(resolve => setTimeout(resolve, 50)))
  expect(api.combinePreview).toHaveBeenCalledTimes(1)
  await user.click(screen.getByRole("radio", { name: "Keep vm-b's" }))
  await waitFor(() => expect(api.combinePreview).toHaveBeenCalledTimes(2))
  await act(() => new Promise(resolve => setTimeout(resolve, 50)))
  expect(api.combinePreview).toHaveBeenCalledTimes(2)
})

it("adds the image decision once a source turns out to carry an image, then settles", async () => {
  const withImage = preview(0)
  withImage.sources[0]!.image = "img-1"
  api.combinePreview.mockResolvedValue(withImage)
  render(<CombineSandboxesDialog first="vm-a" second="vm-b" open onOpenChange={() => {}} />)
  expect(await screen.findByText(/3 vCPU, 2.00 GiB/)).toBeVisible()
  await waitFor(() => expect(api.combinePreview).toHaveBeenLastCalledWith("vm-a", "vm-b", expect.objectContaining({ imageProcess: "once" })))
  await act(() => new Promise(resolve => setTimeout(resolve, 50)))
  expect(api.combinePreview).toHaveBeenCalledTimes(2)
})

it("never offers to combine sandboxes the preview found incompatible", async () => {
  api.combinePreview.mockResolvedValue({ ...preview(0), compatible: false, reasons: ["ID differs"] })
  render(<CombineSandboxesDialog first="vm-a" second="vm-b" open onOpenChange={() => {}} />)
  expect(await screen.findByRole("alert")).toHaveTextContent("ID differs")
  expect(screen.getByRole("button", { name: "Combine" })).toBeDisabled()
})

it("sends a new request key for each click, and the same one only when that click is retried", async () => {
  const user = userEvent.setup()
  api.combinePreview.mockResolvedValue(preview(0))
  api.combineStart
    .mockRejectedValueOnce(new Error("Yougori could not reach the VM sandbox service. Try again."))
    .mockResolvedValueOnce({ operation: "combine-1", state: "rolled-back", failure: "an original did not stop: busy" })
    .mockResolvedValueOnce({ operation: "combine-2", state: "healthy", combined: "vm-c" })
  render(<CombineSandboxesDialog first="vm-a" second="vm-b" open onOpenChange={() => {}} />)
  await user.click(await screen.findByRole("button", { name: "Combine" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("could not reach")
  // The answer never came back: pressing Combine again retries that click with its own key.
  await user.click(screen.getByRole("button", { name: "Combine" }))
  expect(await screen.findByText(/each sandbox it stopped was launched again/)).toBeVisible()
  const keys = api.combineStart.mock.calls.map(call => call[4] as string)
  expect(keys[1]).toBe(keys[0])
  // The failure says why, and the person can go back to the preview and try again.
  expect(screen.getByText("an original did not stop: busy")).toBeVisible()
  await user.click(screen.getByRole("button", { name: "Back to the preview" }))
  await user.click(await screen.findByRole("button", { name: "Combine" }))
  expect(await screen.findByText(/Combined into vm-c/)).toBeVisible()
  const fresh = api.combineStart.mock.calls[2]![4] as string
  expect(fresh).toMatch(/^desktop-/)
  expect(fresh).not.toBe(keys[0])
})

it("shows why a combine failed and offers the preview again instead of a dead end", async () => {
  const user = userEvent.setup()
  api.combinePreview.mockResolvedValue(preview(0))
  api.combineStart.mockResolvedValue({
    operation: "combine-1", state: "failed", failure: "The combined workspace's listing inside the VM was cut off",
    relaunched: [{ from: "vm-a", sandbox: "vm-a2" }, { from: "vm-b", error: "no room" }],
  })
  render(<CombineSandboxesDialog first="vm-a" second="vm-b" open onOpenChange={() => {}} />)
  await user.click(await screen.findByRole("button", { name: "Combine" }))
  expect(await screen.findByText("The combine failed.")).toBeVisible()
  expect(screen.getByText(/listing inside the VM was cut off/)).toBeVisible()
  expect(screen.getByText(/launched again as vm-a2/)).toBeVisible()
  expect(screen.getByText(/not launched again \(no room\)/)).toBeVisible()
  expect(screen.queryByText(/This combine is failed/)).toBeNull()
  await user.click(screen.getByRole("button", { name: "Back to the preview" }))
  expect(await screen.findByText(/3 vCPU, 2.00 GiB/)).toBeVisible()
  expect(api.combinePreview).toHaveBeenCalledTimes(2)
})
