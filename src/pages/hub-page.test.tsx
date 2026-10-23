// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { HubDetail, HubInstance, HubReview, HubSummary } from "@/api/hub-api"

const api = vi.hoisted(() => ({
  list: vi.fn(), detail: vi.fn(), file: vi.fn(), star: vi.fn(), instances: vi.fn(), openConsole: vi.fn(), folder: vi.fn(),
  pageUrl: (item: { publisher: string; name: string }) => `https://yougori.com/hub/${item.publisher}/${item.name}`,
}))
const toasts = vi.hoisted(() => [] as { title: string; description?: string; type?: string }[])
vi.mock("@/api/hub-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/hub-api")>()), hubApi: api }))
vi.mock("@/api/workspace-api", () => ({ workspaceApi: { openUrl: vi.fn(() => Promise.resolve()) } }))
vi.mock("@/components/ui/toast", () => ({ toastManager: { add: (toast: { title: string }) => { toasts.push(toast) } } }))

import { HubPage } from "./hub-page"

const at = 1760000000
const summary = (over: Partial<HubSummary> = {}): HubSummary => ({
  ref: "ana/my-api", publisher: "ana", name: "my-api", kind: "template", title: "My API", summary: "A private model API website.",
  topics: ["ai"], license: "MIT", verified: false, latestVersion: "1.0.0", createdAt: at, updatedAt: at,
  counts: { clones: 12, clonesWeek: 3, stars: 4, forks: 1, versions: 1 }, forkedFrom: null, ...over,
})
const detail = (over: Partial<HubDetail> = {}): HubDetail => ({
  ...summary(), state: "active", removed: null, starred: false, mine: false,
  versions: [{ version: "1.0.0", createdAt: at, digest: "a".repeat(64), verified: false, fileCount: 2, bytes: 300, clones: 12, changelog: "First version." }],
  version: {
    version: "1.0.0", createdAt: at, digest: "a".repeat(64), verified: false, fileCount: 2, bytes: 300, changelog: "First version.",
    readme: "# My API\n\n![Verified](https://evil.example/badge.svg)\n\n<img src=x onerror=alert(1)>",
    files: [{ path: "README.md", bytes: 100, sha256: "b".repeat(64), text: true }, { path: "my file.txt", bytes: 5, sha256: "c".repeat(64), text: true }],
    review: { environments: [{ name: "web", type: "container", image: "node:24", cpu: 2, memoryGb: 4, ports: [3000], tools: ["codex"] }], inputs: [{ id: "key", question: "OpenAI API key", type: "secret", secret: true }] },
    notices: [],
  },
  ...over,
})

beforeEach(() => {
  api.list.mockResolvedValue({ items: [summary({ verified: true, ref: "yougori/hello-site", publisher: "yougori", name: "hello-site", title: "Hello site" }), summary()], total: 2, page: 1, pageSize: 24 })
  api.detail.mockResolvedValue(detail())
  api.openConsole.mockResolvedValue({ opened: true, command: "yougori run hub/ana/my-api@1.0.0" })
  api.instances.mockResolvedValue([])
})
afterEach(() => { cleanup(); vi.clearAllMocks(); toasts.length = 0 })

it("lists Hub items with the Verified badge only on owner uploads", async () => {
  render(<HubPage />)
  const rows = await screen.findAllByRole("button", { name: /clones/ })
  expect(rows).toHaveLength(2)
  expect(within(rows[0]!).getByText("Verified")).toBeInTheDocument()
  expect(within(rows[1]!).queryByText("Verified")).toBeNull()
  expect(screen.getByText(/Community uploads are not checked by Yougori/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Tools" }))
  await waitFor(() => expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ kind: "tool" })))
})

it("shows the warning on an unverified item, never renders README images or HTML, and runs it through a console", async () => {
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  expect(await screen.findByRole("note")).toHaveTextContent("Not checked by Yougori. Community templates can contain harmful code, including viruses.")
  const readme = screen.getByRole("article", { name: "README" })
  expect(readme.querySelector("img")).toBeNull()
  expect(readme).toHaveTextContent("[image: Verified]")
  expect(readme).toHaveTextContent("<img src=x onerror=alert(1)>")
  fireEvent.click(screen.getByRole("button", { name: /Run on this computer/ }))
  await waitFor(() => expect(api.openConsole).toHaveBeenCalledWith("run", "hub/ana/my-api@1.0.0"))
  expect(toasts.at(-1)?.description).toContain("Review what it does there before you confirm")
  fireEvent.click(screen.getByRole("button", { name: "What it creates" }))
  expect(screen.getByText("node:24")).toBeInTheDocument()
  expect(screen.getByText(/OpenAI API key · kept secret, never uploaded/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Files 2" }))
  expect(screen.getByRole("button", { name: "README.md" })).toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "my file.txt" })).toBeNull()
})

it("a malformed review and a very long file cannot break the item page", async () => {
  const base = detail()
  const review = { environments: "web", warnings: "careful", public: [{ environment: "web", port: 3000, access: 5 }], tools: [{ name: "x", downloads: "https://a.example" }], totals: [] } as unknown as HubReview
  api.detail.mockResolvedValueOnce({ ...base, version: { ...base.version!, review } })
  api.file.mockResolvedValueOnce({ path: "README.md", bytes: 60_000, sha256: "b".repeat(64), text: true, content: "line\n".repeat(12_000) })
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  fireEvent.click(await screen.findByRole("button", { name: "What it creates" }))
  expect(screen.getByText("web, port 3000: you choose when it runs")).toBeInTheDocument()
  expect(screen.getByRole("note")).toHaveTextContent("Not checked by Yougori.")
  fireEvent.click(screen.getByRole("button", { name: "Files 2" }))
  fireEvent.click(screen.getByRole("button", { name: "README.md" }))
  await waitFor(() => expect(screen.getByRole("list", { name: "Contents of README.md" }).children).toHaveLength(5000))
  expect(screen.getByText(/Showing the first 5,000 of 12,000 lines/)).toBeInTheDocument()
})

it("a verified item has no warning; a removed one says why and cannot run", async () => {
  api.detail.mockResolvedValueOnce(detail({ verified: true }))
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[0]!)
  expect(await screen.findByText("Verified", { selector: ".hub-detail-title *" })).toBeInTheDocument()
  expect(screen.queryByRole("note")).toBeNull()
  fireEvent.click(screen.getByRole("button", { name: "Back" }))
  api.detail.mockResolvedValueOnce(detail({ state: "removed", removed: { reason: "harmful", message: "Removed by Yougori: harmful code.", at }, versions: [], version: null }))
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  expect(await screen.findByRole("alert")).toHaveTextContent("Removed by Yougori: harmful code. It can no longer be downloaded or run.")
  expect(screen.queryByRole("button", { name: /Run on this computer/ })).toBeNull()
})

it("lists templates on this computer and removes one only after a confirmation", async () => {
  const instance: HubInstance = {
    schema: 1, name: "my-api", ref: "ana/my-api", source: "hub", state: "incomplete", version: "1.0.0", updatedAt: at,
    failed: { part: "tools", message: "Codex did not install in my-api-paid.", next: "yougori template run hub/ana/my-api --name my-api" },
    public: { web: "https://quick.example.trycloudflare.com" }, steps: [{ title: "Sign in to Codex", command: "yougori codex --environment my-api-paid" }],
  }
  api.instances.mockResolvedValue([instance])
  render(<HubPage />)
  fireEvent.click(screen.getByRole("button", { name: "On this computer" }))
  expect(await screen.findByText("Not finished")).toBeInTheDocument()
  expect(screen.getByRole("alert")).toHaveTextContent("Codex did not install in my-api-paid.")
  expect(screen.getByText("https://quick.example.trycloudflare.com")).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Remove…" }))
  expect(api.openConsole).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button", { name: "Remove" }))
  await waitFor(() => expect(api.openConsole).toHaveBeenCalledWith("remove", "my-api"))
  fireEvent.click(screen.getByRole("button", { name: "Status" }))
  await waitFor(() => expect(api.openConsole).toHaveBeenCalledWith("status", "my-api"))
})

it("a run whose window was closed reads as not finished and continues through a console", async () => {
  const now = Math.floor(Date.now() / 1000)
  const base: HubInstance = { schema: 1, name: "shop", ref: "ana/shop", source: "hub", state: "creating", version: "1.0.0", next: "yougori template continue shop" }
  api.instances.mockResolvedValue([{ ...base, updatedAt: now - 600 }, { ...base, name: "blog", ref: "ana/blog", updatedAt: now - 5, next: "yougori template continue blog" }])
  render(<HubPage />)
  fireEvent.click(screen.getByRole("button", { name: "On this computer" }))
  const [stale, live] = await screen.findAllByText(/^(shop|blog)$/, { selector: "strong" })
  const card = (node: HTMLElement) => node.closest(".hub-instance") as HTMLElement
  expect(within(card(stale!)).getByText("Not finished")).toBeInTheDocument()
  expect(within(card(stale!)).getByRole("alert")).toHaveTextContent("This run stopped before it finished")
  expect(within(card(stale!)).getByRole("alert")).toHaveTextContent("yougori template continue shop")
  expect(within(card(live!)).getByText("Being created")).toBeInTheDocument()
  expect(within(card(live!)).queryByRole("button", { name: "Continue" })).toBeNull()
  fireEvent.click(within(card(stale!)).getByRole("button", { name: "Continue" }))
  await waitFor(() => expect(api.openConsole).toHaveBeenCalledWith("continue", "shop"))
})

it("publishes a chosen folder through the CLI, and does nothing when no folder is chosen", async () => {
  api.folder.mockResolvedValueOnce(null).mockResolvedValueOnce("C:\\Users\\me\\hello-site")
  render(<HubPage />)
  fireEvent.click(screen.getByRole("button", { name: "Publish" }))
  fireEvent.click(screen.getByRole("button", { name: /Publish a template folder/ }))
  await waitFor(() => expect(api.folder).toHaveBeenCalledTimes(1))
  expect(api.openConsole).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button", { name: /Publish a template folder/ }))
  await waitFor(() => expect(api.openConsole).toHaveBeenCalledWith("publishTemplate", "C:\\Users\\me\\hello-site"))
})

it("tells people to sign in when starring needs an account", async () => {
  api.star.mockRejectedValueOnce(new Error("Sign in first"))
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  fireEvent.click(await screen.findByRole("button", { name: /^Star/ }))
  await waitFor(() => expect(toasts.at(-1)?.description).toBe("Sign in to the Yougori Network first: run yougori login, then try again."))
})
