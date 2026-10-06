// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import "@testing-library/jest-dom/vitest"
import { ConfidentialNetworkChat } from "./confidential-network-chat"
const mocks = vi.hoisted(() => ({ invoke: vi.fn(), isTauri: vi.fn() }))
vi.mock("@tauri-apps/api/core", () => mocks)
beforeEach(() => { mocks.isTauri.mockReturnValue(true) })
afterEach(() => { cleanup(); vi.resetAllMocks() })
function form() {
  render(<ConfidentialNetworkChat />)
  fireEvent.click(screen.getByRole("button", { name: "Confidential inference" }))
  fireEvent.change(screen.getByLabelText("Local attestation policy"), { target: { value: "C:/verified/policy.json" } })
  fireEvent.change(screen.getByLabelText("Provider ID"), { target: { value: "nd_example" } })
  fireEvent.change(screen.getByLabelText("Model repository"), { target: { value: "hf.co/test/model" } })
  fireEvent.change(screen.getByLabelText("Network API key"), { target: { value: "synthetic-key" } })
  fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "synthetic private prompt" } })
  return screen.getByRole("button", { name: "Verify and send encrypted" })
}
it("uses direct native encryption without storing keys or conversation history", async () => {
  mocks.invoke.mockResolvedValue({ choices: [{ message: { content: "decrypted test reply" } }] })
  const store = vi.spyOn(Storage.prototype, "setItem")
  fireEvent.click(form())
  expect(await screen.findByLabelText("Decrypted response")).toHaveTextContent("decrypted test reply")
  expect(mocks.invoke).toHaveBeenCalledWith("confidential_network_chat", { apiKey: "synthetic-key", nodeId: "nd_example", model: "test/model", prompt: "synthetic private prompt", policyPath: "C:/verified/policy.json" })
  expect(screen.getByLabelText("Network API key")).toHaveValue("")
  expect(store).not.toHaveBeenCalled(); store.mockRestore()
})
it("reports attestation denial without falling back to another inference path", async () => {
  mocks.invoke.mockRejectedValue("No independently approved policy. No prompt was sent.")
  fireEvent.click(form())
  expect(await screen.findByRole("alert")).toHaveTextContent("No prompt was sent")
  expect(mocks.invoke).toHaveBeenCalledTimes(1)
  expect(screen.queryByLabelText("Decrypted response")).not.toBeInTheDocument()
  await waitFor(() => expect(screen.getByLabelText("Network API key")).toHaveValue(""))
})
