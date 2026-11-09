// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { Environment } from "@/types/platform"
import { ModelEnvironmentActions } from "./model-environment-actions"
import { modelsApi } from "@/api/projects-api"
import { workspaceApi } from "@/api/workspace-api"

vi.mock("@/api/projects-api", () => ({ modelsApi: { api: vi.fn(), status: vi.fn() } }))
vi.mock("@/api/workspace-api", () => ({ workspaceApi: { services: vi.fn() } }))
const environment = { id: "model-a", kind: "container", status: "running", description: "Hugging Face · owner/model" } as Environment
const clipboard = vi.fn()
const onChat = vi.fn()
beforeEach(() => {
  vi.resetAllMocks()
  vi.stubGlobal("PointerEvent", MouseEvent)
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: clipboard.mockResolvedValue(undefined) } })
  vi.mocked(workspaceApi.services).mockResolvedValue({ services: [], shares: [], notice: "", publications: [{ id: "pub-model", environmentId: "model-a", kind: "loopback", port: 8000, hostPort: 8123, urls: ["http://127.0.0.1:8123"], status: "active", message: "" }] })
  vi.mocked(modelsApi.api).mockResolvedValue({ id: "model-a", model: "owner/model", apiUrl: "http://127.0.0.1:8123/v1", apiKey: "private-test-key" })
  vi.mocked(modelsApi.status).mockResolvedValue({ status: "ready", model: "owner/model", error: null, task: "text-generation" })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
it("shows model actions only for model containers and targets the selected environment", async () => {
  const view = render(<ModelEnvironmentActions onChat={onChat} environment={{ ...environment, description: "Ordinary GPU container" }} />)
  expect(screen.queryByRole("button", { name: "Chat" })).toBeNull()
  view.rerender(<ModelEnvironmentActions onChat={onChat} environment={environment} />)
  fireEvent.click(screen.getByRole("button", { name: "Chat" }))
  expect(onChat).toHaveBeenCalledOnce()
  expect(screen.queryByRole("dialog")).toBeNull()
  expect(modelsApi.api).not.toHaveBeenCalled()
})
it("reuses the existing API port and copies usable instructions without credentials", async () => {
  render(<ModelEnvironmentActions onChat={onChat} environment={environment} />)
  fireEvent.click(screen.getByRole("button", { name: "API skill" }))
  await waitFor(() => expect(screen.getByLabelText("Local API port")).toHaveValue(8123))
  expect(modelsApi.api).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button", { name: "Enable / get API access" }))
  expect(await screen.findByLabelText("Model API key")).toHaveAttribute("type", "password")
  expect(modelsApi.api).toHaveBeenCalledExactlyOnceWith("model-a", 8123)
  fireEvent.click(screen.getByRole("button", { name: "Copy API skill" }))
  await screen.findByText("API skill copied")
  const skill = clipboard.mock.calls[0]![0] as string
  expect(skill).toContain("http://127.0.0.1:8123/v1/chat/completions")
  expect(skill).toContain('"model": "owner/model"')
  expect(skill).toContain('os.environ["YOUGORI_MODEL_API_KEY"]')
  expect(skill).not.toContain("private-test-key")
})
it("blocks API changes for stopped models", async () => {
  render(<ModelEnvironmentActions onChat={onChat} environment={{ ...environment, status: "stopped" }} />)
  fireEvent.click(screen.getByRole("button", { name: "API skill" }))
  expect(await screen.findByRole("button", { name: "Enable / get API access" })).toBeDisabled()
  expect(modelsApi.api).not.toHaveBeenCalled()
})
it("reports API failures without presenting stale credentials", async () => {
  vi.mocked(modelsApi.api).mockRejectedValue(new Error("Port is already in use"))
  render(<ModelEnvironmentActions onChat={onChat} environment={environment} />)
  fireEvent.click(screen.getByRole("button", { name: "API skill" }))
  fireEvent.click(await screen.findByRole("button", { name: "Enable / get API access" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("Port is already in use")
  expect(screen.queryByLabelText("Model API key")).toBeNull()
})
