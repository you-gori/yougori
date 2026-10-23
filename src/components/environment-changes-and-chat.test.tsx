// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { EnvironmentChanges } from "./environment-changes"
import { ModelChat } from "./model-workspace"
import { changesApi, modelsApi } from "@/api/projects-api"

vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ refreshPlatform: vi.fn().mockResolvedValue(undefined), state: { environments: [] } }) }))
vi.mock("@/api/projects-api", () => ({ changesApi: { inspect: vi.fn() }, modelsApi: { status: vi.fn(), chat: vi.fn(), run: vi.fn() } }))
afterEach(cleanup)
beforeEach(() => { vi.clearAllMocks() })
describe("environment changes and model chat", () => {
  it("shows exact counts and a real diff and confirms baseline replacement", async () => {
    vi.mocked(changesApi.inspect).mockResolvedValue({ available: true, baselineAt: "2026-09-20T12:00:00Z", summary: { modified: 23, created: 4, deleted: 2, renamed: 1, variables: 3, packagesInstalled: 6, packagesChanged: 6, configuration: 1 }, files: [{ folder: "C:/project", path: "app.ts", kind: "modified", beforeBytes: 7, afterBytes: 6, diff: "--- a/app.ts\n+++ b/app.ts\n-before\n+after\n" }], variables: [{ name: "TOKEN", before: "[redacted]", after: "[redacted]" }] })
    render(<EnvironmentChanges environmentId="env-test" />)
    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: "Changes" }))
    const counts = await screen.findByLabelText("Change counts")
    expect(within(counts).getByText("23")).toBeInTheDocument()
    expect(screen.getByText("app.ts")).toBeInTheDocument()
    await user.click(screen.getByText("app.ts"))
    expect(screen.getByText("-before")).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "New baseline" }))
    expect(changesApi.inspect).not.toHaveBeenCalledWith("env-test", true, 0)
    await user.click(screen.getByRole("button", { name: "Save new baseline" }))
    await waitFor(() => expect(changesApi.inspect).toHaveBeenCalledWith("env-test", true, 0))
  })
  it("waits for model readiness and sends the conversation to the selected environment", async () => {
    vi.mocked(modelsApi.status).mockResolvedValue({ status: "ready", model: "TinyLlama/test", error: null })
    vi.mocked(modelsApi.chat).mockResolvedValue({ choices: [{ message: { content: "Hello from your GPU" } }] })
    render(<ModelChat environmentId="env-model" />)
    const user = userEvent.setup()
    await screen.findByText(/TinyLlama\/test/)
    await user.type(screen.getByRole("textbox", { name: "Message your model" }), "Hello")
    await user.click(screen.getByRole("button", { name: "Send message" }))
    expect(await screen.findByText("Hello from your GPU")).toBeInTheDocument()
    expect(modelsApi.chat).toHaveBeenCalledWith("env-model", [{ role: "user", content: "Hello" }], { maxTokens: 1024, temperature: 0.7 })
  })
})
