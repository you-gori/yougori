import { afterEach, expect, it, vi } from "vitest"
import { modelsApi } from "./projects-api"

const tauri = vi.hoisted(() => ({ invoke: vi.fn(), Channel: class { onmessage?: (event: unknown) => void } }))
vi.mock("@tauri-apps/api/core", () => ({ invoke: tauri.invoke, Channel: tauri.Channel, isTauri: () => true }))
afterEach(() => { vi.clearAllMocks() })

const options = { maxTokens: 64, temperature: 0.2 }

it("does not start generation when the chat was stopped before the stream began", async () => {
  const controller = new AbortController()
  controller.abort()
  await expect(modelsApi.stream("model", [{ role: "user", content: "hi" }], options, () => undefined, controller.signal)).resolves.toEqual({ finishReason: "cancelled" })
  expect(tauri.invoke).not.toHaveBeenCalled()
})

it("cancels a running stream by request id when the signal aborts", async () => {
  const controller = new AbortController()
  let finish!: (value: unknown) => void
  tauri.invoke.mockImplementation((command: string) => command === "model_chat_stream" ? new Promise(resolve => { finish = resolve }) : Promise.resolve())
  const reply = modelsApi.stream("model", [{ role: "user", content: "hi" }], options, () => undefined, controller.signal)
  await vi.waitFor(() => expect(tauri.invoke).toHaveBeenCalledWith("model_chat_stream", expect.objectContaining({ environmentId: "model" })))
  const requestId = tauri.invoke.mock.calls[0]![1].requestId
  controller.abort()
  expect(tauri.invoke).toHaveBeenCalledWith("model_chat_cancel", { requestId })
  finish({ finishReason: "cancelled" })
  await expect(reply).resolves.toEqual({ finishReason: "cancelled" })
})
