// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ModelLibrary } from "./model-library"
const calls = vi.hoisted(() => ({ list: vi.fn(), folder: vi.fn(), download: vi.fn(), openUrl: vi.fn(), refresh: vi.fn() }))
vi.mock("@/api/model-registry-api", () => ({ registryApi: calls }))
vi.mock("@/api/workspace-api", () => ({ workspaceApi: { openUrl: calls.openUrl } }))
vi.mock("@/components/network-panel", () => ({ NetworkAccount: () => <p>Wallet account</p> }))
vi.mock("@/components/use-network", () => ({ useNetwork: () => ({ status: { signedIn: true, website: "https://yougori.com" }, refresh: calls.refresh }) }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ state: { environments: [{ id: "env-test", name: "Tiny", description: "Hugging Face · owner/tiny", status: "running" }] } }) }))
const model = { id: "rm_test", ref: "yg/alice/tiny", name: "Tiny model", description: "My model", license: "MIT", visibility: "public", owned: true, canHost: true, canDownload: true, price: null, royaltyPercent: 0, version: { id: "rv_test", label: "v1", source: "upload", delivery: "yougori", quant: null } }
beforeEach(() => { calls.list.mockResolvedValue({ models: [model] }); calls.folder.mockResolvedValue("D:/Models/tiny"); calls.openUrl.mockResolvedValue(undefined); calls.refresh.mockResolvedValue({}) })
afterEach(() => { cleanup(); vi.resetAllMocks() })
it("opens the website upload flow without requiring a model container", async () => {
  render(<ModelLibrary onRun={vi.fn()} />)
  fireEvent.click(screen.getByRole("button", { name: "Model library" }))
  fireEvent.click(await screen.findByRole("button", { name: "Publish" }))
  fireEvent.click(screen.getByRole("button", { name: "Upload a model" }))
  expect(calls.openUrl).toHaveBeenCalledWith("https://yougori.com/publish")
  expect(screen.queryByLabelText("Running model container")).not.toBeInTheDocument()
})
it("downloads stored Yougori files to a chosen folder and can select them for hosting", async () => {
  const run = vi.fn(); render(<ModelLibrary onRun={run} />)
  fireEvent.click(screen.getByRole("button", { name: "Model library" }))
  fireEvent.click(await screen.findByRole("button", { name: "Tiny model · public" }))
  fireEvent.click(screen.getByRole("button", { name: "Download model files" }))
  await waitFor(() => expect(calls.download).toHaveBeenCalledWith("yg/alice/tiny", "D:/Models/tiny"))
  await waitFor(() => expect(screen.getByRole("button", { name: "Run on my GPU" })).toBeEnabled())
  fireEvent.click(screen.getByRole("button", { name: "Run on my GPU" }))
  expect(run).toHaveBeenCalledWith("yg/alice/tiny", undefined)
})
it("closed model pages offer chat and API without download or hosting controls", async () => {
  calls.list.mockResolvedValue({ models: [{ ...model, visibility: "api-only", canDownload: false }] })
  render(<ModelLibrary onRun={vi.fn()} />)
  fireEvent.click(screen.getByRole("button", { name: "Model library" }))
  fireEvent.click(await screen.findByRole("button", { name: "Tiny model · Closed weights" }))
  expect(screen.getByRole("button", { name: "Model card and files" })).toBeVisible()
  expect(screen.queryByRole("button", { name: "Download model files" })).not.toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "Run on my GPU" })).not.toBeInTheDocument()
})
