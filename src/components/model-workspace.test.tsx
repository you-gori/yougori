// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ModelChat, ModelWorkspace } from "./model-workspace"

const { status, chat, run, preflight, stream, history, saveHistory, platform } = vi.hoisted(() => ({ status: vi.fn(), chat: vi.fn(), run: vi.fn(), preflight:vi.fn(), stream: vi.fn(), history: vi.fn(), saveHistory: vi.fn(), platform: { state: { environments: [] as { id: string; status: string; lastError?: string }[] }, environmentActions: {}, setEnvironmentStatus: vi.fn(), refreshPlatform: vi.fn() } }))
const market = vi.hoisted(() => ({ status: vi.fn(), signIn: vi.fn(), share: vi.fn(), listen: vi.fn(async () => () => {}) }))
vi.mock("@/api/market-api", () => ({ marketApi: market }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => platform }))
vi.mock("@/api/projects-api", () => ({ modelsApi: { status, chat, run, preflight, stream, history, saveHistory } }))
// An in-memory engine store for chat history.
let savedHistory: unknown = null
beforeEach(() => { savedHistory = null; history.mockImplementation(async () => savedHistory); saveHistory.mockImplementation(async (_id: string, value: unknown) => { savedHistory = value }) })
vi.mock("@/components/guest-logs", () => ({
  GuestLogs: ({ environmentId, active }: { environmentId: string; active: boolean }) =>
    <div aria-label="Live startup output">{active ? environmentId : "paused"}</div>,
}))
afterEach(() => { cleanup(); vi.resetAllMocks(); vi.useRealTimers(); localStorage.clear(); platform.state.environments = [] })

it("rejects an unsupported decision model before creating a chat environment", async () => {
  preflight.mockResolvedValue({supported:false,task:"structured-decision",reason:"Use the model's dedicated SDK/decision API",resources:{storageGbRecommended:null},downloads:{}})
  render(<ModelWorkspace />)
  fireEvent.click(screen.getByRole("button", {name:"Huggingface"}))
  fireEvent.click(await screen.findByRole("button", {name:"Check compatibility"}))
  expect(await screen.findByLabelText("Model compatibility")).toHaveTextContent("Requires a dedicated runner")
  expect(screen.getByRole("button", {name:"Run model"})).toBeDisabled()
  expect(run).not.toHaveBeenCalled()
})

it("requires browser sign-in before creating a shared model", async () => {
  market.status.mockResolvedValue({ signedIn: false, shares: [], login: null })
  market.signIn.mockResolvedValue({})
  render(<ModelWorkspace />)
  fireEvent.click(screen.getByRole("button", { name: "Huggingface" }))
  fireEvent.click(await screen.findByRole("button", { name: "Free (--nowfree)" }))
  fireEvent.click(screen.getByRole("button", { name: "Run model" }))
  await waitFor(() => expect(market.signIn).toHaveBeenCalledOnce())
  expect(run).not.toHaveBeenCalled()
  expect(await screen.findByRole("alert")).toHaveTextContent("Approve the sign-in code")
})

it("passes GGUF quantization and shares the created model for free", async () => {
  market.status.mockResolvedValue({ signedIn: true, account: { email: "user@example.com", wallet: null, creditMicros: 0, earningsMicros: 0, availableMicros: 0 }, shares: [] })
  run.mockResolvedValue({ id: "new-model", model: "example/model" })
  market.share.mockResolvedValue({})
  render(<ModelWorkspace />)
  fireEvent.click(screen.getByRole("button", { name: "Huggingface" }))
  fireEvent.change(await screen.findByLabelText("GGUF quantization (optional)"), { target: { value: "Q8_0" } })
  fireEvent.click(screen.getByRole("button", { name: "Free (--nowfree)" }))
  fireEvent.click(screen.getByRole("button", { name: "Run model" }))
  await waitFor(() => expect(run).toHaveBeenCalledWith("hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0", null, "Q8_0"))
  await waitFor(() => expect(market.share).toHaveBeenCalledWith("new-model", "free"))
})

it("allows another message after a model restarts during generation and ignores the old reply", async () => {
  let finishOld!: (value: unknown) => void
  let finishNew!: (value: unknown) => void
  status.mockResolvedValue({ status: "ready", model: "example/model", error: null })
  chat.mockImplementationOnce(() => new Promise(resolve => { finishOld = resolve }))
    .mockImplementationOnce(() => new Promise(resolve => { finishNew = resolve }))
  platform.state.environments = [{ id: "model-one", status: "running" }]
  const view = render(<ModelChat environmentId="model-one" />)
  fireEvent.change(screen.getByLabelText("Message your model"), { target: { value: "First message" } })
  await waitFor(() => expect(screen.getByRole("button", { name: "Send message" })).toBeEnabled())
  fireEvent.click(screen.getByRole("button", { name: "Send message" }))
  expect(chat).toHaveBeenCalledTimes(1)

  platform.state.environments = [{ id: "model-one", status: "stopped" }]
  view.rerender(<ModelChat environmentId="model-one" />)
  expect(screen.getByLabelText("Message your model")).toBeEnabled()
  platform.state.environments = [{ id: "model-one", status: "running" }]
  view.rerender(<ModelChat environmentId="model-one" />)
  fireEvent.change(screen.getByLabelText("Message your model"), { target: { value: "Second message" } })
  await waitFor(() => expect(screen.getByRole("button", { name: "Send message" })).toBeEnabled())
  fireEvent.click(screen.getByRole("button", { name: "Send message" }))
  expect(chat).toHaveBeenCalledTimes(2)
  await act(async () => { finishOld({ choices: [{ message: { content: "Obsolete reply" } }] }) })
  expect(screen.queryByText("Obsolete reply")).not.toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Stop generating" })).toBeInTheDocument()
  await act(async () => { finishNew({ choices: [{ message: { content: "Current reply" } }] }) })
  expect(screen.getByText("Current reply")).toBeInTheDocument()
  expect(screen.getByLabelText("Message your model")).toBeEnabled()
})

it("shows live logs even while the health endpoint is unavailable", async () => {
  status.mockRejectedValue(new Error("Model server is starting"))
  render(<ModelChat environmentId="model-one" />)
  expect(screen.getByLabelText("Live startup output")).toHaveTextContent("model-one")
  expect(screen.getByText("Startup logs").closest("details")).toHaveAttribute("open")
  expect(await screen.findByRole("alert")).toHaveTextContent("Model server is starting")
  expect(screen.getByRole("button", { name: "Send message" })).toBeDisabled()
})

it("does not overlap health requests and stops polling after leaving", async () => {
  vi.useFakeTimers()
  let resolve!: (value: unknown) => void
  status.mockImplementationOnce(() => new Promise(done => { resolve = done }))
  const view = render(<ModelChat environmentId="model-one" />)
  await act(async () => { await vi.advanceTimersByTimeAsync(20000) })
  expect(status).toHaveBeenCalledTimes(1)
  await act(async () => { resolve({ status: "ready", model: "example/model", error: null }) })
  expect(screen.getByText("Startup logs").closest("details")).not.toHaveAttribute("open")
  view.unmount()
  await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
  expect(status).toHaveBeenCalledTimes(1)
})

it("does not request model health until container provisioning finishes", async () => {
  platform.state.environments = [{ id: "model-one", status: "provisioning" }]
  render(<ModelChat environmentId="model-one" />)
  expect(status).not.toHaveBeenCalled()
  expect(screen.getByRole("status")).toHaveTextContent("Downloading and preparing container image")
  expect(screen.getByLabelText("Live startup output")).toHaveTextContent("model-one")
  platform.state.environments = []
})

it("closes the model dialog immediately while creation continues", async () => {
  let finish!: (value: unknown) => void
  run.mockImplementation(() => new Promise(resolve => { finish = resolve }))
  platform.refreshPlatform.mockResolvedValue(undefined)
  render(<ModelWorkspace />)
  fireEvent.click(screen.getByRole("button", { name: "Huggingface" }))
  fireEvent.click(await screen.findByRole("button", { name: "Run model" }))
  expect(run).toHaveBeenCalledOnce()
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  await act(async () => { finish({ id: "model-1", model: "TinyLlama/TinyLlama-1.1B-Chat-v1.0" }) })
})

it("streams replies with the system prompt, shows context use and keeps the conversation", async () => {
  status.mockResolvedValue({ status: "ready", model: "example/model", error: null, stream: true, context: 4096 })
  stream.mockImplementation(async (_id: string, _messages: unknown, _options: unknown, onDelta: (text: string) => void) => {
    onDelta("Here is **bold** and code:\n\n```py\nprint(1)\n")
    onDelta("```")
    return { finishReason: "stop", usage: { prompt_tokens: 900, completion_tokens: 124, total_tokens: 1024, truncated_messages: 0, context_window: 4096 } }
  })
  platform.state.environments = [{ id: "model-one", status: "running" }]
  const view = render(<ModelChat environmentId="model-one" />)
  fireEvent.click(screen.getByRole("button", { name: "Settings" }))
  await waitFor(() => expect(screen.getByLabelText("System prompt")).toBeEnabled())
  fireEvent.change(screen.getByLabelText("System prompt"), { target: { value: "Answer like a pirate." } })
  fireEvent.change(screen.getByLabelText("Temperature"), { target: { value: "0.2" } })
  fireEvent.change(screen.getByLabelText("Message your model"), { target: { value: "Hi there" } })
  await waitFor(() => expect(screen.getByRole("button", { name: "Send message" })).toBeEnabled())
  fireEvent.keyDown(screen.getByLabelText("Message your model"), { key: "Enter" })
  expect(await screen.findByText("bold")).toContainHTML("<strong>bold</strong>")
  expect(screen.getByText("print(1)").closest("pre")).toBeInTheDocument()
  expect(stream).toHaveBeenCalledWith("model-one", [{ role: "system", content: "Answer like a pirate." }, { role: "user", content: "Hi there" }], { maxTokens: 1024, temperature: 0.2 }, expect.any(Function), expect.any(AbortSignal))
  expect(screen.getByText(/124 tokens/)).toBeInTheDocument()
  expect(screen.getByTitle("1,024 of 4,096 tokens")).toHaveTextContent("1.0k / 4.1k")
  view.unmount()
  expect(saveHistory).toHaveBeenLastCalledWith("model-one", expect.objectContaining({ settings: expect.objectContaining({ system: "Answer like a pirate.", temperature: 0.2 }) }))
  render(<ModelChat environmentId="model-one" />)
  expect(await screen.findByRole("button", { name: "Delete Hi there" })).toBeInTheDocument()
  expect(screen.getByRole("log")).toHaveTextContent("Hi there")
})

it("stops a streaming reply and regenerates from the same user message", async () => {
  status.mockResolvedValue({ status: "ready", model: "example/model", error: null, stream: true, context: 2048 })
  stream.mockImplementationOnce((_id: string, _messages: unknown, _options: unknown, onDelta: (text: string) => void, signal: AbortSignal) => {
    onDelta("Partial answer")
    return new Promise(resolve => signal.addEventListener("abort", () => resolve({ finishReason: "cancelled" })))
  }).mockImplementationOnce(async (_id: string, _messages: unknown, _options: unknown, onDelta: (text: string) => void) => {
    onDelta("Complete answer")
    return { finishReason: "stop" }
  })
  platform.state.environments = [{ id: "model-one", status: "running" }]
  render(<ModelChat environmentId="model-one" />)
  fireEvent.change(screen.getByLabelText("Message your model"), { target: { value: "Question" } })
  await waitFor(() => expect(screen.getByRole("button", { name: "Send message" })).toBeEnabled())
  fireEvent.click(screen.getByRole("button", { name: "Send message" }))
  expect(await screen.findByText("Partial answer")).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Stop generating" }))
  expect(await screen.findByText("Stopped")).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Regenerate" }))
  expect(await screen.findByText("Complete answer")).toBeInTheDocument()
  expect(screen.queryByText("Partial answer")).not.toBeInTheDocument()
  expect(stream).toHaveBeenLastCalledWith("model-one", [{ role: "user", content: "Question" }], expect.anything(), expect.any(Function), expect.any(AbortSignal))
})

it("never overwrites saved chats when they cannot be loaded", async () => {
  history.mockRejectedValue(new Error("engine unavailable"))
  status.mockResolvedValue({ status: "ready", model: "example/model", error: null })
  chat.mockResolvedValue({ choices: [{ message: { content: "Reply" } }] })
  platform.state.environments = [{ id: "model-one", status: "running" }]
  render(<ModelChat environmentId="model-one" />)
  fireEvent.change(screen.getByLabelText("Message your model"), { target: { value: "Hello" } })
  await waitFor(() => expect(screen.getByRole("button", { name: "Send message" })).toBeEnabled())
  fireEvent.click(screen.getByRole("button", { name: "Send message" }))
  expect(await screen.findByText("Reply")).toBeInTheDocument()
  await new Promise(resolve => setTimeout(resolve, 500))
  expect(saveHistory).not.toHaveBeenCalled()
})

it("keeps a failed autosave pending and retries without changing the conversation", async () => {
  status.mockResolvedValue({ status: "ready", model: "example/model", error: null })
  saveHistory.mockRejectedValueOnce(new Error("engine unavailable"))
  render(<ModelChat environmentId="model-one" />)
  fireEvent.click(screen.getByRole("button", { name: "Settings" }))
  await waitFor(() => expect(screen.getByLabelText("System prompt")).toBeEnabled())
  fireEvent.change(screen.getByLabelText("System prompt"), { target: { value: "Keep this prompt" } })
  await waitFor(() => expect(saveHistory).toHaveBeenCalledTimes(1))
  expect(await screen.findByRole("alert")).toHaveTextContent("Chat history couldn't be saved")
  fireEvent.click(screen.getByRole("button", { name: "Retry saving" }))
  await waitFor(() => expect(saveHistory).toHaveBeenCalledTimes(2))
  expect(saveHistory).toHaveBeenLastCalledWith("model-one", expect.objectContaining({ settings: expect.objectContaining({ system: "Keep this prompt" }) }))
  await waitFor(() => expect(screen.queryByRole("button", { name: "Retry saving" })).not.toBeInTheDocument())
})

it("serializes autosaves so a slower old request cannot replace the latest settings", async () => {
  let finishFirst!: () => void
  status.mockResolvedValue({ status: "ready", model: "example/model", error: null })
  saveHistory.mockImplementationOnce(() => new Promise<void>(resolve => { finishFirst = resolve }))
  render(<ModelChat environmentId="model-one" />)
  fireEvent.click(screen.getByRole("button", { name: "Settings" }))
  await waitFor(() => expect(screen.getByLabelText("System prompt")).toBeEnabled())
  fireEvent.change(screen.getByLabelText("System prompt"), { target: { value: "First prompt" } })
  await waitFor(() => expect(saveHistory).toHaveBeenCalledTimes(1))
  fireEvent.change(screen.getByLabelText("System prompt"), { target: { value: "Latest prompt" } })
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 500)) })
  expect(saveHistory).toHaveBeenCalledTimes(1)
  await act(async () => { finishFirst() })
  await waitFor(() => expect(saveHistory).toHaveBeenCalledTimes(2))
  expect(saveHistory).toHaveBeenLastCalledWith("model-one", expect.objectContaining({ settings: expect.objectContaining({ system: "Latest prompt" }) }))
})
