// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { ModelUsagePanel } from "./model-usage-panel"

const { usage } = vi.hoisted(() => ({ usage: vi.fn() }))
vi.mock("@/api/projects-api", () => ({ modelsApi: { usage } }))
afterEach(() => { cleanup(); vi.resetAllMocks() })

const now = Math.floor(Date.now() / 1000)
const data = {
  since: now - 86400, totals: { requests: 3, prompt_tokens: 300, completion_tokens: 90, errors: 1, rejected: 2 },
  hours: { [String(Math.floor(now / 3600))]: { requests: 3, prompt_tokens: 300, completion_tokens: 90, errors: 1, rejected: 2, yougori: 1, api: 2 } },
  recent: [
    { time: now - 60, source: "yougori", outcome: "ok", prompt_tokens: 200, completion_tokens: 80, seconds: 2, stream: true },
    { time: now - 30, source: "api", outcome: "rejected", prompt_tokens: 0, completion_tokens: 0, seconds: 0, stream: false },
  ],
}

it("shows totals, a per-day chart and recent requests, and resets after confirmation", async () => {
  usage.mockResolvedValue(data)
  render(<ModelUsagePanel environmentId="model-one" />)
  expect(await screen.findByText("1 chat · 2 API")).toBeInTheDocument()
  expect(screen.getByText("1 failed · 2 wrong key")).toBeInTheDocument()
  expect(screen.getByText("40.0")).toBeInTheDocument()
  expect(screen.getAllByRole("button", { name: /requests, / })).toHaveLength(7)
  fireEvent.click(screen.getByRole("button", { name: "30 days" }))
  expect(screen.getAllByRole("button", { name: /requests, / })).toHaveLength(30)
  expect(screen.getByText("Wrong API key")).toBeInTheDocument()
  expect(screen.getByText("40.0 tok/s")).toBeInTheDocument()
  usage.mockResolvedValue({ ...data, totals: { requests: 0, prompt_tokens: 0, completion_tokens: 0, errors: 0, rejected: 0 }, hours: {}, recent: [] })
  fireEvent.click(screen.getByRole("button", { name: "Reset usage" }))
  expect(usage).not.toHaveBeenCalledWith("model-one", true)
  fireEvent.click(screen.getByRole("button", { name: "Clear usage history" }))
  await waitFor(() => expect(usage).toHaveBeenCalledWith("model-one", true))
  expect(await screen.findByText(/No requests yet/)).toBeInTheDocument()
})

it("explains how to enable tracking on models started by an older version", async () => {
  usage.mockRejectedValue("Run this model again from Hugging Face to track usage")
  render(<ModelUsagePanel environmentId="model-one" />)
  expect(await screen.findByRole("alert")).toHaveTextContent("Run this model again")
})

it("shows the free-provider recording location instead of claiming content is never stored", async () => {
  usage.mockResolvedValue({ ...data, listen: { enabled: true, path: "/root/.cache/huggingface/yougori-listen/requests.jsonl" } })
  render(<ModelUsagePanel environmentId="model-one" />)
  expect(await screen.findByText("/root/.cache/huggingface/yougori-listen/requests.jsonl")).toBeInTheDocument()
  expect(screen.getByText(/Free-provider recording is on/)).toBeInTheDocument()
  expect(screen.queryByText(/never recorded/)).not.toBeInTheDocument()
})
