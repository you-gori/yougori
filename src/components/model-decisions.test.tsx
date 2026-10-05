// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { ModelDecisions } from "./model-decisions"
const { chat } = vi.hoisted(() => ({ chat: vi.fn() }))
vi.mock("@/api/projects-api", () => ({ modelsApi: { chat } }))
afterEach(() => { cleanup(); vi.resetAllMocks() })
const status = { status: "ready" as const, model: "Cloudflare/clef", error: null, task: "structured-decision", precision: "4bit" }
it("sends state and typed questions and displays probabilities", async () => {
  chat.mockResolvedValue({ choices: [{ message: { content: JSON.stringify({ answers: { route: { choice: "technical", probabilities: { technical: 0.9, billing: 0.1 } } } }) } }] })
  render(<ModelDecisions environmentId="model-1" status={status} />)
  fireEvent.change(screen.getByLabelText("State (text or JSON)"), { target: { value: '{"service":"checkout"}' } })
  fireEvent.click(screen.getByRole("button", { name: "Run decision" }))
  await waitFor(() => expect(chat).toHaveBeenCalledOnce())
  expect(JSON.parse(chat.mock.calls[0]![1][0].content)).toMatchObject({ state: { service: "checkout" }, questions: { route: { type: "choice" } } })
  expect(await screen.findByLabelText("Decision result")).toHaveTextContent('"technical": 0.9')
  expect(screen.getByText(/Quantized inference can change probabilities/)).toBeInTheDocument()
})
it("rejects malformed questions before sending inference", async () => {
  render(<ModelDecisions environmentId="model-1" status={status} />)
  fireEvent.change(screen.getByLabelText("Questions (JSON)"), { target: { value: '[]' } })
  fireEvent.click(screen.getByRole("button", { name: "Run decision" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("Questions must be a JSON object")
  expect(chat).not.toHaveBeenCalled()
})
