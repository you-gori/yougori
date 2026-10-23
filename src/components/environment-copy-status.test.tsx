// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import type { DuplicationJob } from "@/api/duplication-api"
import type { Environment } from "@/types/platform"
import { EnvironmentCopyStatus } from "./environment-copy-status"

const cleanupCopy = vi.fn()
const abandonCopy = vi.fn()
vi.mock("@/api/duplication-api", async original => ({ ...await original<typeof import("@/api/duplication-api")>(), duplicationApi: { cleanup: (id: string) => cleanupCopy(id), abandon: (id: string) => abandonCopy(id) } }))
let platform: { state: { environments: Environment[]; duplicationJobs: Record<string, DuplicationJob> }; refreshPlatform(): Promise<void> }
vi.mock("@/context/platform-context", () => ({ usePlatform: () => platform }))

afterEach(() => { cleanup(); cleanupCopy.mockReset(); abandonCopy.mockReset() })

const environment = (id: string, name: string) => ({ id, name } as Environment)
const source = environment("env-source", "Web server")
const copy = environment("env-copy", "Web server copy")
const job = (over: Partial<DuplicationJob>): DuplicationJob => ({
  request: { operationId: "op-1", environmentId: source.id, name: "Web server copy", destination: "cloud", source: null, target: { provider: "aws" } as DuplicationJob["request"]["target"], targetBucket: "", storageDrive: null, reviewed: true },
  environmentId: copy.id, status: "failed", phase: "Importing the disk", error: null, resources: [], ...over,
})
const show = (row: Environment, jobs: DuplicationJob[], environments = [source, copy]) => {
  platform = { state: { environments, duplicationJobs: Object.fromEntries(jobs.map((item, index) => [`op-${index + 1}`, item])) }, refreshPlatform: vi.fn(async () => undefined) }
  const onOpen = vi.fn()
  render(<EnvironmentCopyStatus environment={row} onOpen={onOpen} />)
  return onOpen
}

it("offers to remove what a finished copy could not, because it is billed until it goes", async () => {
  cleanupCopy.mockResolvedValue({})
  show(copy, [job({ status: "complete", error: "The environment was copied. Some transfer resources still need cleanup:\nRemove AMI", completed: {} })])
  expect(screen.getByRole("status")).toHaveTextContent("still at AWS, and they are billed until they go")
  fireEvent.click(screen.getByRole("button", { name: "Remove them" }))
  await waitFor(() => expect(cleanupCopy).toHaveBeenCalledWith("op-1"))
  expect(platform.refreshPlatform).toHaveBeenCalled()
})

it("says nothing about a copy that finished and cleaned up after itself", () => {
  show(copy, [job({ status: "complete", completed: { cleanup: true } })])
  expect(screen.queryByRole("status")).toBeNull()
})

it("sends a copy that stopped part way to where it can be resumed or discarded", () => {
  const onOpen = show(copy, [job({ status: "failed" })])
  expect(screen.getByRole("status")).toHaveTextContent("This copy stopped part way.")
  fireEvent.click(screen.getByRole("button", { name: "Resume or discard" }))
  expect(onOpen).toHaveBeenCalledWith(source.id, "cloud")
})

it("tells a copy's original about it while the copy has no environment of its own yet", () => {
  const onOpen = show(source, [job({ status: "interrupted", request: { ...job({}).request, destination: "local", localFiles: { image: "ubuntu", paths: ["~"], storageGb: 20 } } })], [source])
  expect(screen.getByRole("status")).toHaveTextContent("The copy Web server copy stopped part way.")
  fireEvent.click(screen.getByRole("button", { name: "Resume or discard" }))
  expect(onOpen).toHaveBeenCalledWith(source.id, "local")
})

it("shows a running copy's progress once, on the copy's own row", () => {
  show(copy, [job({ status: "running" })])
  expect(screen.getByRole("status")).toHaveTextContent("Being copied: Importing the disk…")
  cleanup()
  show(source, [job({ status: "running" })])
  expect(screen.queryByRole("status")).toBeNull()
})

it("lets a copy whose original is gone be discarded, or says where its resources are", async () => {
  cleanupCopy.mockResolvedValue({})
  show(copy, [job({ status: "failed" })], [copy])
  expect(screen.getByRole("status")).toHaveTextContent("Its original is gone, so it cannot be resumed.")
  fireEvent.click(screen.getByRole("button", { name: "Discard it" }))
  await waitFor(() => expect(cleanupCopy).toHaveBeenCalledWith("op-1"))
  cleanup()
  show(copy, [job({ status: "failed", resources: ["AMI ami-123 (source image)"], pending: "import" })], [copy])
  expect(screen.queryByRole("button")).toBeNull()
  expect(screen.getByText(/ami-123/)).toHaveTextContent("remove it in AWS’s console, where it carries this copy’s ID, op-1")
})

it("gives a copy up only from the question that says it cannot be resumed afterwards", async () => {
  abandonCopy.mockResolvedValue({})
  show(copy, [job({ status: "failed", resources: ["AMI ami-123 (source image)"] })], [copy])
  fireEvent.click(screen.getByRole("button", { name: "Give up this copy" }))
  expect(abandonCopy).not.toHaveBeenCalled()
  const question = await screen.findByRole("alertdialog")
  expect(question).toHaveTextContent("This removes the disks and images this copy made at AWS, and the copy cannot be resumed afterwards.")
  fireEvent.click(screen.getByRole("button", { name: "Keep the copy" }))
  expect(abandonCopy).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button", { name: "Give up this copy" }))
  fireEvent.click(await screen.findByRole("button", { name: "Remove them and give up" }))
  await waitFor(() => expect(abandonCopy).toHaveBeenCalledWith("op-1"))
  expect(cleanupCopy).not.toHaveBeenCalled()
})
