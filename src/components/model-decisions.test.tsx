// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ModelDecisions } from "./model-decisions"
const { chat, history, saveHistory } = vi.hoisted(() => ({ chat: vi.fn(), history: vi.fn(), saveHistory: vi.fn() }))
vi.mock("@/api/projects-api", () => ({ modelsApi: { chat, history, saveHistory } }))
beforeEach(() => { history.mockResolvedValue(null); saveHistory.mockResolvedValue(undefined) })
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

it("restores CLI JSON history and appends decisions to the same session", async () => {
  const payload = {state:'CLI state',questions:{risk:{type:'noul'}}}
  const result = {answers:{risk:{type:'noul',noul:0.9}}}
  history.mockResolvedValue({activeId:'shared-session',conversations:[{id:'shared-session',title:'From CLI',updatedAt:1,messages:[{id:'request',role:'user',content:JSON.stringify(payload)},{id:'answer',role:'assistant',content:JSON.stringify(result)}]}]})
  chat.mockResolvedValue({choices:[{message:{content:JSON.stringify(result)}}],usage:{prompt_tokens:42,completion_tokens:0}})
  render(<ModelDecisions environmentId="model-1" status={status} />)
  await waitFor(() => expect(screen.getByLabelText('State (text or JSON)')).toHaveValue('CLI state'))
  expect(await screen.findByLabelText('Decision result')).toHaveTextContent('0.9')
  fireEvent.change(screen.getByLabelText('State (text or JSON)'), {target:{value:'New app state'}})
  fireEvent.click(screen.getByRole('button',{name:'Run decision'}))
  await waitFor(() => expect(saveHistory).toHaveBeenCalledOnce())
  const saved=saveHistory.mock.calls[0]![1]
  expect(saved.activeId).toBe('shared-session')
  expect(saved.conversations).toHaveLength(1)
  expect(saved.conversations[0].messages).toHaveLength(4)
  expect(JSON.parse(saved.conversations[0].messages[2].content).state).toBe('New app state')
  expect(saved.conversations[0].messages[3].stats.inputTokens).toBe(42)
})
