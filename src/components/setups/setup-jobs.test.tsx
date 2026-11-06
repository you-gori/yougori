// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, expect, it, vi } from "vitest"
import type { ResourceView } from "@/api/setups/types"

const api = vi.hoisted(() => ({ jobLogs: vi.fn(), settleJob: vi.fn(), artifacts: vi.fn(), saveArtifact: vi.fn(), sandboxLogs: vi.fn(), usage: vi.fn() }))
vi.mock("@/api/setups/setups-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/setups-api")>()), setupsApi: api }))

import { SetupUnavailableError } from "@/api/setups/setups-api"
import { SetupArtifacts, SetupJobs, SetupModelUsage, SetupSandboxLogs } from "./setup-jobs"

const part = (resourceId: string, kind: ResourceView["kind"], over: Partial<ResourceView> = {}): ResourceView => ({ resourceId, kind, owned: true, label: resourceId, observed: "present", ...over })

afterEach(() => {
  cleanup()
  for (const call of Object.values(api)) call.mockReset()
})

it("lists only the setup's own jobs and shows what an attempt printed on request", async () => {
  api.jobLogs.mockResolvedValue([{ attempt: "attempt-0123456789abcdef", at: null, text: "built 3 files" }])
  const user = userEvent.setup()
  render(<SetupJobs setupId="acme" parts={[part("nightly", "job"), part("borrowed", "job", { owned: false }), part("web", "environment")]} />)
  expect(screen.getByText("nightly")).toBeInTheDocument()
  expect(screen.queryByText("borrowed")).not.toBeInTheDocument()
  expect(screen.queryByText("web")).not.toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "It did its work" })).not.toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "What it printed" }))
  expect(api.jobLogs).toHaveBeenCalledWith("acme", "nightly")
  expect(await screen.findByLabelText("What attempt attempt-0123456789abcdef printed")).toHaveTextContent("built 3 files")
})

it("offers to settle a job nobody knows the outcome of, and not while the setup is changing", async () => {
  api.settleJob.mockResolvedValue({ state: "succeeded" })
  const user = userEvent.setup()
  const { rerender } = render(<SetupJobs setupId="acme" parts={[part("nightly", "job", { observed: "unknown" })]} moving />)
  expect(screen.getByRole("button", { name: "It did its work" })).toBeDisabled()
  rerender(<SetupJobs setupId="acme" parts={[part("nightly", "job", { observed: "unknown" })]} />)
  await user.click(screen.getByRole("button", { name: "It did its work" }))
  expect(api.settleJob).toHaveBeenCalledWith("acme", "nightly", "succeeded")
  expect(await screen.findByRole("status")).toHaveTextContent("Settled: it is succeeded now.")
})

it("shows nothing for a setup without jobs", () => {
  const { container } = render(<SetupJobs setupId="acme" parts={[part("web", "environment")]} />)
  expect(container).toBeEmptyDOMElement()
})

it("lists results with their size, and a removed one without a save", async () => {
  api.artifacts.mockResolvedValue([
    { id: "a-1", resource: "nightly", name: "report.pdf", bytes: 2048, sha256: "x", recordedAt: 1_761_444_000, removed: false },
    { id: "a-2", resource: null, name: "old.zip", bytes: 10, sha256: "y", recordedAt: 1_761_000_000, removed: true, removedBecause: "older than 30 days" },
  ])
  render(<SetupArtifacts setupId="acme" />)
  const list = await screen.findByRole("list", { name: "Results its jobs handed back" })
  expect(list).toHaveTextContent("report.pdf")
  expect(list).toHaveTextContent("from nightly")
  expect(list).toHaveTextContent("removed by the store's retention: older than 30 days")
  expect(screen.getAllByRole("button", { name: "Save…" })).toHaveLength(1)
})

it("says plainly when this build can't list results", async () => {
  api.artifacts.mockRejectedValue(new SetupUnavailableError("setup_artifacts"))
  render(<SetupArtifacts setupId="acme" />)
  expect(await screen.findByRole("status")).toHaveTextContent("This build of Yougori can't show that yet.")
})

it("reads one sandbox's log at a time, and says when only the end is shown", async () => {
  api.sandboxLogs.mockResolvedValue({ text: "listening on 3000", truncated: true })
  const user = userEvent.setup()
  render(<SetupSandboxLogs setupId="acme" parts={[part("web", "environment"), part("nightly", "job")]} />)
  expect(screen.queryByRole("button", { name: "nightly" })).not.toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "web" }))
  expect(api.sandboxLogs).toHaveBeenCalledWith("acme", "web")
  expect(await screen.findByLabelText("What web printed")).toHaveTextContent("listening on 3000")
  expect(screen.getByText("Only the end is shown.")).toBeInTheDocument()
})

it("shows a cloud model's spend against its budget and warns close to it", async () => {
  api.usage.mockResolvedValue([{ resource: "model_gateway", model: "openai/gpt-5-mini", spentUsd: 17, budgetUsd: 20, requests: 40, refused: 1, freeOnly: false }])
  render(<SetupModelUsage setupId="acme" />)
  expect(await screen.findByText("openai/gpt-5-mini")).toBeInTheDocument()
  expect(screen.getByText(/\$17\.0000 of \$20\.00 spent, 40 requests, 1 refused/)).toBeInTheDocument()
  expect(screen.getByRole("status")).toHaveTextContent("It is close to its budget.")
})
