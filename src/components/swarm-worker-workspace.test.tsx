// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { swarmApi } from "@/api/swarm-api"
import { SwarmWorkerWorkspace } from "./swarm-worker-workspace"
import { mergeActivity } from "@/lib/swarm-activity"

vi.mock("@/api/swarm-api", () => ({ swarmApi: { activity: vi.fn(), messages: vi.fn(), reports: vi.fn() } }))
beforeEach(() => {
  vi.useFakeTimers()
  HTMLElement.prototype.scrollTo = vi.fn()
  vi.mocked(swarmApi.messages).mockResolvedValue({ messages: [] })
  vi.mocked(swarmApi.reports).mockResolvedValue({ reports: [] })
  vi.mocked(swarmApi.activity).mockResolvedValue({ worker: {} as never, events: [], latest: 0 })
})
afterEach(() => { cleanup(); vi.useRealTimers(); vi.clearAllMocks() })

it("updates one row while the model writes and keeps the draft across tabs", async () => {
  vi.mocked(swarmApi.activity)
    .mockResolvedValueOnce({ worker: {} as never, events: [{ seq: 1, streamId: "s:1", text: "Checking", streaming: true }], latest: 1 })
    .mockResolvedValue({ worker: {} as never, events: [{ seq: 2, streamId: "s:1", text: "Checking the file", streaming: false }], latest: 2 })
  await act(async () => { render(<SwarmWorkerWorkspace workerId="worker" hasBounty onChanged={() => {}} />) })
  expect(screen.getByRole("tab", { name: "Activity" }).getAttribute("aria-selected")).toBe("true")
  expect(screen.getByRole("log", { name: "Worker activity" }).textContent).toContain("Checking")
  await act(async () => { await vi.advanceTimersByTimeAsync(750) })
  expect(screen.getByRole("log", { name: "Worker activity" }).querySelectorAll("p")).toHaveLength(1)
  expect(screen.getByText("Checking the file")).toBeTruthy()
  fireEvent.click(screen.getByRole("tab", { name: "Conversation" }))
  fireEvent.change(screen.getByRole("textbox", { name: "Message the worker" }), { target: { value: "Keep this draft" } })
  fireEvent.click(screen.getByRole("tab", { name: "Activity" }))
  expect(screen.queryByRole("textbox", { name: "Message the worker" })).toBeNull()
  fireEvent.click(screen.getByRole("tab", { name: "Conversation" }))
  expect((screen.getByRole("textbox", { name: "Message the worker" }) as HTMLTextAreaElement).value).toBe("Keep this draft")
})

it("reconnects from full snapshots without duplicating or regressing text", () => {
  const complete = { seq: 5, streamId: "s:1", text: "Complete" }
  expect(mergeActivity([], [complete, { seq: 4, streamId: "s:1", text: "Partial" }, complete])).toEqual([complete])
  expect(mergeActivity([complete], [{ seq: 6, kind: "action" }])).toHaveLength(2)
})

it("follows new activity to the bottom even after scrolling up", async () => {
  vi.mocked(swarmApi.activity)
    .mockResolvedValueOnce({ worker: {} as never, events: [{ seq: 1, streamId: "s:1", text: "First" }], latest: 1 })
    .mockResolvedValue({ worker: {} as never, events: [{ seq: 2, streamId: "s:1", text: "First and second" }], latest: 2 })
  await act(async () => { render(<SwarmWorkerWorkspace workerId="worker" hasBounty={false} onChanged={() => {}} />) })
  const log = screen.getByRole("log", { name: "Worker activity" })
  Object.defineProperties(log, { scrollHeight: { value: 1000 }, clientHeight: { value: 320 } })
  fireEvent.scroll(log, { target: { scrollTop: 100 } })
  vi.mocked(HTMLElement.prototype.scrollTo).mockClear()
  await act(async () => { await vi.advanceTimersByTimeAsync(750) })
  expect(screen.getByText("First and second")).toBeTruthy()
  expect(HTMLElement.prototype.scrollTo).toHaveBeenCalledWith({ top: 1000, behavior: "instant" })
})

it("opens both tabs at the bottom even when their content arrived while hidden", async () => {
  await act(async () => { render(<SwarmWorkerWorkspace workerId="worker" hasBounty onChanged={() => {}} />) })
  const activity = screen.getByRole("log", { name: "Worker activity" })
  const conversation = screen.getByRole("log", { name: "Conversation with the worker", hidden: true })
  Object.defineProperty(activity, "scrollHeight", { value: 1400 })
  Object.defineProperty(conversation, "scrollHeight", { value: 2200 })
  activity.scrollTo = vi.fn()
  conversation.scrollTo = vi.fn()
  fireEvent.click(screen.getByRole("tab", { name: "Conversation" }))
  expect(conversation.scrollTo).toHaveBeenLastCalledWith({ top: 2200, behavior: "instant" })
  expect(activity.scrollTo).not.toHaveBeenCalled()
  vi.mocked(swarmApi.activity).mockResolvedValue({ worker: {} as never, events: [{ seq: 1, text: "New activity" }], latest: 1 })
  vi.mocked(swarmApi.messages).mockResolvedValue({ messages: [{ id: "message", sequence: 1, role: "worker", content: "New reply" }] })
  await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
  expect(conversation.scrollTo).toHaveBeenCalledTimes(2)
  expect(activity.scrollTo).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("tab", { name: "Activity" }))
  expect(activity.scrollTo).toHaveBeenLastCalledWith({ top: 1400, behavior: "instant" })
})

it("does not overlap slow polls and retries after a connection failure", async () => {
  let reject!: (error: Error) => void
  vi.mocked(swarmApi.activity).mockImplementationOnce(() => new Promise((_, fail) => { reject = fail }))
  await act(async () => { render(<SwarmWorkerWorkspace workerId="worker" hasBounty={false} onChanged={() => {}} />) })
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(swarmApi.activity).toHaveBeenCalledOnce()
  await act(async () => { reject(new Error("Offline")) })
  expect(screen.getByRole("status").textContent).toContain("Reconnecting")
  await act(async () => { await vi.advanceTimersByTimeAsync(750) })
  expect(swarmApi.activity).toHaveBeenCalledTimes(2)
  expect(screen.queryByRole("status")).toBeNull()
})
