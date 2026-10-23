// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { swarmApi, type SwarmPrompts } from "@/api/swarm-api"
import { SwarmPromptsEditor } from "./swarm-prompts"

vi.mock("@/api/swarm-api", () => ({ swarmApi: { prompts: vi.fn(), savePrompts: vi.fn(), resetPrompts: vi.fn() } }))
vi.mock("@/components/ui/toast", () => ({ toastManager: { add: vi.fn() } }))
const field = { value: "original", default: "original", custom: true }
const initial: SwarmPrompts = { agents: field, rules: field, liveTask: field, sourceTask: field, chatReply: field, placeholders: { liveTask: [], sourceTask: [] } }
beforeEach(() => { vi.mocked(swarmApi.prompts).mockResolvedValue(initial) })
afterEach(() => { cleanup(); vi.resetAllMocks() })

it.each(["Save", "Reset to default"])("%s preserves other fields' drafts, including edits during the request", async action => {
  let resolve!: (value: SwarmPrompts) => void
  vi.mocked(swarmApi.savePrompts).mockReturnValue(new Promise(done => { resolve = done }))
  await act(async () => { render(<SwarmPromptsEditor />) })
  fireEvent.change(screen.getByLabelText("Agent core instructions"), { target: { value: "saved agents" } })
  fireEvent.change(screen.getByLabelText("Worker rules & guardrails"), { target: { value: "unsaved rules" } })
  fireEvent.click(screen.getAllByRole("button", { name: action })[0]!)
  fireEvent.change(screen.getByLabelText("Worker rules & guardrails"), { target: { value: "newer unsaved rules" } })
  await act(async () => { resolve({ ...initial, agents: { ...field, value: "saved agents" } }) })
  expect((screen.getByLabelText("Worker rules & guardrails") as HTMLTextAreaElement).value).toBe("newer unsaved rules")
  expect((screen.getByLabelText("Agent core instructions") as HTMLTextAreaElement).value).toBe("saved agents")
})

it("shows a load failure and lets the user retry", async () => {
  vi.mocked(swarmApi.prompts).mockRejectedValueOnce(new Error("Disconnected"))
  await act(async () => { render(<SwarmPromptsEditor />) })
  expect(screen.getByRole("alert").textContent).toContain("Disconnected")
  expect(screen.queryByText("Loading the prompts…")).toBeNull()
  await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Retry" })) })
  expect(screen.getByLabelText("Agent core instructions")).toBeTruthy()
})
