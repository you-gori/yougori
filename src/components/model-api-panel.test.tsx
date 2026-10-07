// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ModelApiPanel } from "./model-api-panel"

const { access, api, status, workspace } = vi.hoisted(() => ({ access: vi.fn(), api: vi.fn(), status: vi.fn(), workspace: { publish: vi.fn(), unpublish: vi.fn(), savedCloudflare: vi.fn(), copySavedCloudflareToPreset: vi.fn(), openUrl: vi.fn(), forgetCloudflare: vi.fn() } }))
vi.mock("@/api/projects-api", () => ({ modelsApi: { access, api, status } }))
vi.mock("@/api/workspace-api", () => ({ workspaceApi: workspace }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ state: { environments: [{ id: "model-one", status: "running" }] } }) }))
afterEach(() => { cleanup(); vi.resetAllMocks(); vi.unstubAllGlobals(); localStorage.clear() })
beforeEach(() => { vi.stubGlobal("PointerEvent", MouseEvent); workspace.savedCloudflare.mockResolvedValue({ saved: false, hostname: "", hostPort: null }) })

const off = { id: "model-one", model: "owner/model", apiKey: "k".repeat(64), apiUrl: null, publicUrl: null, publicId: null, publicAccount: false }

it("source-only publishers offer downloads without inference keys or examples", async () => {
  access.mockResolvedValue(off)
  status.mockResolvedValue({ status: "ready", sourceOnly: true, inferenceAvailable: false })
  render(<ModelApiPanel environmentId="model-one" />)
  expect(await screen.findByRole("region", { name: "Source-only API" })).toBeVisible()
  expect(screen.queryByLabelText("Model API key")).not.toBeInTheDocument()
  expect(screen.queryByText(/base_url=/)).not.toBeInTheDocument()
})

it("connects a quick link and shows ready-to-use examples without the key", async () => {
  access.mockResolvedValueOnce(off).mockResolvedValueOnce({ ...off, publicUrl: "https://abc.trycloudflare.com/v1", publicId: "pub-1" }).mockResolvedValueOnce(off)
  status.mockResolvedValue({ status: "ready", model: "owner/model", error: null, stream: true })
  render(<ModelApiPanel environmentId="model-one" />)
  expect(await screen.findByText("Examples appear here once an address is on.")).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Set up public access" }))
  fireEvent.click(await screen.findByRole("button", { name: "Connect" }))
  await waitFor(() => expect(workspace.publish).toHaveBeenCalledWith("model-one", 8000, "cloudflare", undefined, undefined))
  expect(await screen.findByText(/Quick link. Lasts while Yougori runs/)).toBeInTheDocument()
  const code = screen.getByText(/base_url="https:\/\/abc.trycloudflare.com\/v1"/)
  expect(code).toHaveTextContent("stream=True")
  expect(code).not.toHaveTextContent("k".repeat(64))
  expect(screen.getByLabelText("Model API key")).toHaveAttribute("type", "password")
  fireEvent.click(screen.getByRole("button", { name: "Agent skill" }))
  expect(screen.getByText(/works from any computer/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Turn off" }))
  await waitFor(() => expect(workspace.unpublish).toHaveBeenCalledWith("pub-1"))
  expect(await screen.findByRole("button", { name: "Set up public access" })).toBeInTheDocument()
})

it("connects the model API to the user's own Cloudflare domain", async () => {
  access.mockResolvedValueOnce(off).mockResolvedValueOnce({ ...off, publicUrl: "https://llm.example.com/v1", publicId: "pub-2", publicAccount: true })
  status.mockResolvedValue({ status: "ready", model: "owner/model", error: null, stream: true })
  workspace.copySavedCloudflareToPreset.mockResolvedValue(undefined)
  render(<ModelApiPanel environmentId="model-one" />)
  fireEvent.click(await screen.findByRole("button", { name: "Set up public access" }))
  const accountMode = screen.getByRole("radio", { name: "Use my Cloudflare account (optional)" })
  await waitFor(() => expect(accountMode).not.toHaveAttribute("data-disabled"))
  fireEvent.click(accountMode)
  fireEvent.change(screen.getByPlaceholderText("app.example.com"), { target: { value: "llm.example.com" } })
  fireEvent.change(screen.getByPlaceholderText("45000"), { target: { value: "45123" } })
  fireEvent.change(screen.getByPlaceholderText("Paste token or Cloudflare command"), { target: { value: "token-value" } })
  fireEvent.click(screen.getByRole("checkbox", { name: /reviewed this dedicated tunnel/ }))
  fireEvent.click(screen.getByRole("button", { name: "Connect" }))
  await waitFor(() => expect(workspace.publish).toHaveBeenCalledWith("model-one", 8000, "cloudflare", 45123, { hostname: "llm.example.com", token: "token-value", remember: true, routesReviewed: true }))
  expect(await screen.findByText("Your Cloudflare domain.")).toBeInTheDocument()
  expect(workspace.copySavedCloudflareToPreset).toHaveBeenCalledWith("model-one", 8000, expect.any(String))
})

it("enables localhost access on the chosen port", async () => {
  access.mockResolvedValueOnce(off).mockResolvedValueOnce({ ...off, apiUrl: "http://127.0.0.1:9100/v1" })
  status.mockResolvedValue({ status: "ready", model: "owner/model", error: null })
  api.mockResolvedValue({})
  render(<ModelApiPanel environmentId="model-one" />)
  fireEvent.change(await screen.findByLabelText("Local API port"), { target: { value: "9100" } })
  fireEvent.click(screen.getByRole("button", { name: "Turn on" }))
  await waitFor(() => expect(api).toHaveBeenCalledWith("model-one", 9100))
  expect(await screen.findByText(/base_url="http:\/\/127.0.0.1:9100\/v1"/)).not.toHaveTextContent("stream=True")
  expect(screen.getByText(/started by an older Yougori/)).toBeInTheDocument()
})

it("reuses a saved domain that was set up for another app port", async () => {
  const id = "3f1c2b8e-4a5d-4e6f-9a7b-1c2d3e4f5a6b"
  localStorage.setItem("yougori.public-access-presets.v1", JSON.stringify([{ id, credentialEnvironmentId: "public-presets", port: 5281, hostname: "crm.prompx.com", hostPort: 5281 }]))
  access.mockResolvedValueOnce(off).mockResolvedValueOnce({ ...off, publicUrl: "https://crm.prompx.com/v1", publicId: "pub-3", publicAccount: true })
  status.mockResolvedValue({ status: "ready", model: "owner/model", error: null, stream: true })
  render(<ModelApiPanel environmentId="model-one" />)
  fireEvent.click(await screen.findByRole("button", { name: "Set up public access" }))
  expect(screen.queryByText(/different port/)).not.toBeInTheDocument()
  const saved = screen.getByRole("radio", { name: "Use crm.prompx.com" })
  await waitFor(() => expect(saved).not.toHaveAttribute("data-disabled"))
  fireEvent.click(saved)
  fireEvent.click(screen.getByRole("button", { name: "Connect" }))
  await waitFor(() => expect(workspace.publish).toHaveBeenCalledWith("model-one", 8000, "cloudflare", 5281, { hostname: "crm.prompx.com", presetId: id, presetSourceEnvironmentId: "public-presets", presetPort: 5281, remember: false, routesReviewed: true }))
  expect(await screen.findByText("Your Cloudflare domain.")).toBeInTheDocument()
})

it("fills the real API key into every example only when asked", async () => {
  access.mockResolvedValue({ ...off, apiUrl: "http://127.0.0.1:8000/v1" })
  status.mockResolvedValue({ status: "ready", model: "owner/model", error: null, stream: true })
  render(<ModelApiPanel environmentId="model-one" />)
  const code = () => screen.getByText(/base_url=|baseURL:|curl |Invoke-RestMethod|name: yougori-model-api/)
  expect(await screen.findByText(/os.environ\["YOUGORI_MODEL_API_KEY"\]/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole("switch", { name: "Include API key" }))
  expect(screen.getByText(/This example contains your API key/)).toBeInTheDocument()
  for (const tab of ["Python", "JavaScript", "curl", "PowerShell", "Agent skill"]) {
    fireEvent.click(screen.getByRole("button", { name: tab }))
    expect(code()).toHaveTextContent("k".repeat(64))
  }
  fireEvent.click(screen.getByRole("switch", { name: "Include API key" }))
  expect(code()).not.toHaveTextContent("k".repeat(64))
})
