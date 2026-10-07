// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ModelLibrary } from "./model-library"
const calls = vi.hoisted(() => ({ list: vi.fn(), folder: vi.fn(), download: vi.fn(), share: vi.fn(), refresh: vi.fn() }))
vi.mock("@/api/model-registry-api", () => ({ registryApi: calls }))
vi.mock("@/api/market-api", () => ({ marketApi: { share: calls.share } }))
vi.mock("@/components/network-panel", () => ({ NetworkAccount: () => <p>Wallet account</p> }))
vi.mock("@/components/use-network", () => ({ useNetwork: () => ({ status: { signedIn: true, website: "https://yougori.com" }, refresh: calls.refresh }) }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ state: { environments: [{ id: "env-test", name: "Tiny", description: "Hugging Face · owner/tiny", status: "running" }] } }) }))
const model = { id: "rm_test", ref: "yg/alice/tiny", name: "Tiny model", description: "My model", license: "MIT", visibility: "public", owned: true, canHost: true, canDownload: true, price: null, royaltyPercent: 0, version: { id: "rv_test", label: "v1", source: "endpoint", delivery: "publisher", quant: null } }
beforeEach(() => { calls.list.mockResolvedValue({ models: [model] }); calls.folder.mockResolvedValue("D:/Models/tiny"); calls.share.mockResolvedValue({ modelPage: "https://yougori.com/models?model=yg/alice/tiny" }); calls.refresh.mockResolvedValue({}) })
afterEach(() => { cleanup(); vi.resetAllMocks() })
it("publishes the existing container in open or closed mode without uploading weights", async () => {
  render(<ModelLibrary onRun={vi.fn()} />)
  fireEvent.click(screen.getByRole("button", { name: "Model library" }))
  fireEvent.click(await screen.findByRole("button", { name: "Publish" }))
  fireEvent.change(screen.getByLabelText("Running model container"), { target: { value: "env-test" } })
  fireEvent.click(screen.getByRole("button", { name: "Publish container" }))
  await waitFor(() => expect(calls.share).toHaveBeenCalledWith("env-test", "free", false))
  await waitFor(() => expect(screen.getByRole("button", { name: "Publish container" })).toBeEnabled())
  fireEvent.click(screen.getByRole("checkbox", { name: /Closed weights/ }))
  fireEvent.click(screen.getByRole("button", { name: "Publish container" }))
  await waitFor(() => expect(calls.share).toHaveBeenCalledWith("env-test", "free", true))
  expect(screen.queryByText("Upload and publish")).not.toBeInTheDocument()
})
it("downloads open publisher files to a chosen folder and can select them for hosting", async () => {
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
  expect(screen.getByRole("button", { name: "Model page, chat and API" })).toBeVisible()
  expect(screen.queryByRole("button", { name: "Download model files" })).not.toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "Run on my GPU" })).not.toBeInTheDocument()
})
