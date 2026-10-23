// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ModelChat } from "./model-chat"

const { status, history, saveHistory, chat, stream, listen } = vi.hoisted(() => ({ status: vi.fn(), history: vi.fn(), saveHistory: vi.fn(), chat: vi.fn(), stream: vi.fn(), listen: vi.fn() }))
vi.mock("@/api/projects-api", () => ({ modelsApi: { status, history, saveHistory, chat, stream } }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ state: null, setEnvironmentStatus: vi.fn(), environmentActions: {} }) }))
vi.mock("@/components/guest-logs", () => ({ GuestLogs: () => null }))
vi.mock("@/components/chat-markdown", () => ({ Markdown: ({ text }: { text: string }) => <p>{text}</p> }))
vi.mock("@tauri-apps/api/event", () => ({ listen }))

/** What the engine tells open windows when a model's conversations were saved, by the CLI say. */
let savedElsewhere: (environmentId: string) => void = () => undefined
beforeEach(() => {
  status.mockResolvedValue({ status: "ready", model: "org/Helper", stream: false, context: 4096, error: null })
  saveHistory.mockResolvedValue(undefined)
  listen.mockImplementation(async (_event: string, handler: (event: { payload: string }) => void) => {
    savedElsewhere = environmentId => handler({ payload: environmentId })
    return () => undefined
  })
  Object.defineProperty(window, "__TAURI_INTERNALS__", { value: {}, configurable: true })
})
afterEach(() => { cleanup(); vi.resetAllMocks(); delete (window as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ })

it("says, for as long as it lasts, that a chat whose saved conversations could not load is not being saved", async () => {
  history.mockRejectedValue(new Error("Saved chat history is unreadable"))
  render(<ModelChat environmentId="model-1" />)
  const notice = await screen.findByText(/this chat isn't being saved/)
  expect(notice).toHaveTextContent("Saved chat history is unreadable")
  expect(notice).toHaveTextContent("Nothing already saved was changed")
  expect(saveHistory).not.toHaveBeenCalled()
})

it("keeps a conversation that is not being saved on screen when the saved ones change elsewhere", async () => {
  history.mockRejectedValueOnce(new Error("Saved chat history is unreadable"))
  chat.mockResolvedValue({ choices: [{ message: { content: "Here is a plan." }, finish_reason: "stop" }], usage: { prompt_tokens: 5, completion_tokens: 4 } })
  render(<ModelChat environmentId="model-1" />)
  fireEvent.change(await screen.findByPlaceholderText("Message Helper…"), { target: { value: "Plan my week" } })
  fireEvent.click(screen.getByRole("button", { name: "Send message" }))
  expect(await screen.findByText("Here is a plan.")).toBeInTheDocument()
  await waitFor(() => expect(listen).toHaveBeenCalled())

  // The CLI saves this model's conversations, and this window hears of it and reads them again.
  history.mockResolvedValue({ conversations: [{ id: "cli", title: "From the CLI", updatedAt: 1, messages: [{ id: "m", role: "user", content: "Hello from the CLI" }] }], activeId: "cli", settings: {} })
  await act(async () => { savedElsewhere("model-1"); await new Promise(resolve => setTimeout(resolve, 0)) })
  expect(history).toHaveBeenCalledTimes(2)
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)) })

  // The conversation the person is having stays; nothing was saved over anything.
  const log = screen.getByRole("log")
  expect(within(log).getByText("Plan my week")).toBeInTheDocument()
  expect(within(log).getByText("Here is a plan.")).toBeInTheDocument()
  expect(screen.queryByText("Hello from the CLI")).not.toBeInTheDocument()
  expect(saveHistory).not.toHaveBeenCalled()
})
